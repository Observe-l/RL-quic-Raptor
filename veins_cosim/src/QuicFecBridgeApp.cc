#include "QuicFecBridgeApp.h"

#include "QuicFecDatagram_m.h"
#include "veins/base/modules/BaseMacLayer.h"
#include "veins/base/phyLayer/PhyToMacControlInfo.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <sstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace omnetpp;
using namespace veins;

namespace veins_cosim {

namespace {
constexpr uint8_t IPC_MAGIC[4] = {'V', 'Q', 'F', '1'};
std::mutex childMutex;
std::vector<pid_t> childPids;

uint16_t get16(const uint8_t* p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

void put16(uint8_t* p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xff);
}

std::vector<std::string> splitWords(const std::string& s)
{
    std::istringstream in(s);
    std::vector<std::string> words;
    std::string word;
    while (in >> word) words.push_back(word);
    return words;
}

void reapChildren()
{
    std::lock_guard<std::mutex> lock(childMutex);
    for (auto it = childPids.begin(); it != childPids.end();) {
        int status = 0;
        pid_t result = waitpid(*it, &status, WNOHANG);
        if (result == *it || (result < 0 && errno == ECHILD)) it = childPids.erase(it);
        else ++it;
    }
}

void stopChildren()
{
    std::vector<pid_t> pids;
    {
        std::lock_guard<std::mutex> lock(childMutex);
        pids.swap(childPids);
    }
    for (pid_t pid : pids) kill(pid, SIGTERM);
    for (pid_t pid : pids) {
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    }
}

bool isChildTracked(pid_t pid)
{
    if (pid <= 0) return false;
    std::lock_guard<std::mutex> lock(childMutex);
    return std::find(childPids.begin(), childPids.end(), pid) != childPids.end();
}

void stopChild(pid_t pid)
{
    if (pid <= 0) return;
    {
        std::lock_guard<std::mutex> lock(childMutex);
        auto it = std::find(childPids.begin(), childPids.end(), pid);
        if (it == childPids.end()) return;
        childPids.erase(it);
    }
    kill(pid, SIGTERM);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}
} // namespace

Define_Module(QuicFecBridgeApp);

QuicFecBridgeApp::~QuicFecBridgeApp()
{
    cancelAndDelete(pollEvent);
    cancelAndDelete(beaconEvent);
    cancelAndDelete(uploadEvent);
    stopChild(childPid);
    if (!currentAliasPath.empty()) unlink(currentAliasPath.c_str());
    if (bridgeFd >= 0) close(bridgeFd);
}

void QuicFecBridgeApp::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        isRSU = par("isRSU").boolValue();
        periodicUploadInterval = par("periodicUploadInterval").doubleValue();
        nodeId = isRSU ? RSU_ID : getParentModule()->getIndex();
        rsuBridgePort = par("rsuBridgePort").intValue();
        bridgePortBase = par("bridgePortBase").intValue();

        bridgeFd = socket(AF_INET, SOCK_DGRAM, 0);
        if (bridgeFd < 0) throw cRuntimeError("socket(): %s", strerror(errno));
        int reuse = 1;
        setsockopt(bridgeFd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        int flags = fcntl(bridgeFd, F_GETFL, 0);
        if (flags < 0 || fcntl(bridgeFd, F_SETFL, flags | O_NONBLOCK) < 0)
            throw cRuntimeError("fcntl(O_NONBLOCK): %s", strerror(errno));

        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        local.sin_port = htons(isRSU ? rsuBridgePort : bridgePortBase + nodeId);
        if (bind(bridgeFd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0)
            throw cRuntimeError("bind bridge port %d: %s", ntohs(local.sin_port), strerror(errno));

        pollEvent = new cMessage("veins-quicfec-poll", pollKind);
        scheduleAt(simTime() + par("pollInterval"), pollEvent);
        if (!isRSU && par("periodicBeaconing").boolValue())
            beaconEvent = new cMessage("veins-quicfec-beacon", beaconKind);
    }
    else if (stage == 1) {
        if (isRSU) {
            EV_WARN << "RSU bridge MAC=" << mac->getMACAddress() << endl;
            childPid = launchChild(true);
        }
        else {
            if (!resolveRsuMac()) throw cRuntimeError("could not resolve RSU MAC address");
            EV_WARN << "vehicle bridge id=" << nodeId << " MAC=" << mac->getMACAddress()
                    << " RSU MAC=" << rsuMacAddress << endl;
            if (periodicUploadInterval > 0) {
                uploadEvent = new cMessage("veins-quicfec-periodic-upload", uploadKind);
                scheduleAt(simTime(), uploadEvent);
            }
            else {
                childPid = launchChild(false);
            }
            if (beaconEvent) scheduleAt(simTime() + uniform(0, par("beaconInterval")), beaconEvent);
        }
    }
}

bool QuicFecBridgeApp::resolveRsuMac()
{
    cModule* rsu = getSimulation()->getSystemModule()->getSubmodule("rsu", 0);
    if (!rsu) return false;
    cModule* nic = rsu->getSubmodule("nic");
    cModule* macModule = nic ? nic->getSubmodule("mac1609_4") : nullptr;
    auto* rsuMac = dynamic_cast<BaseMacLayer*>(macModule);
    if (!rsuMac) return false;
    rsuMacAddress = rsuMac->getMACAddress();
    return rsuMacAddress != LAddress::L2NULL();
}

std::string QuicFecBridgeApp::inputPathForNode() const
{
    char name[64];
    snprintf(name, sizeof(name), "/flow_%04d.bin", nodeId);
    return par("clientInputDir").stdstringValue() + name;
}

pid_t QuicFecBridgeApp::launchChild(bool server, const std::string& fileOverride, int transferSequence)
{
    const std::string binary = par(server ? "serverBin" : "clientBin").stdstringValue();
    if (binary.empty()) throw cRuntimeError("missing %s", server ? "serverBin" : "clientBin");
    const std::string logDir = par("logDir").stdstringValue();
    std::string logName = server ? "/server.log" : "/client_" + std::to_string(nodeId) + ".log";
    if (!server && transferSequence >= 0) {
        char suffix[48];
        snprintf(suffix, sizeof(suffix), "_tx_%06d.log", transferSequence);
        logName = "/client_" + std::to_string(nodeId) + suffix;
    }
    const std::string logPath = logDir + logName;

    std::vector<std::string> args;
    args.push_back(binary);
    auto extra = splitWords(par(server ? "serverOptions" : "clientOptions").stdstringValue());
    args.insert(args.end(), extra.begin(), extra.end());
    if (server) {
        args.emplace_back("-bridge-port");
        args.push_back(std::to_string(rsuBridgePort));
        args.emplace_back("-out");
        args.push_back(par("receiveDir").stdstringValue());
    }
    else {
        args.emplace_back("-bridge-port");
        args.push_back(std::to_string(bridgePortBase + nodeId));
        args.emplace_back("-vehicle-id");
        args.push_back(std::to_string(nodeId));
        args.emplace_back("-file");
        args.push_back(fileOverride.empty() ? inputPathForNode() : fileOverride);
    }

    pid_t pid = fork();
    if (pid < 0) throw cRuntimeError("fork(): %s", strerror(errno));
    if (pid == 0) {
        int fd = open(logPath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > STDERR_FILENO) close(fd);
        }
        setenv("QUIC_FEC_CC_ALGO", "bbrv2", 1);
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        execv(binary.c_str(), argv.data());
        _exit(127);
    }
    {
        std::lock_guard<std::mutex> lock(childMutex);
        childPids.push_back(pid);
    }
    EV_INFO << "started " << (server ? "QUIC-FEC server" : "QUIC-FEC client")
            << " process pid=" << pid << (server ? "" : " vehicle=" + std::to_string(nodeId)) << endl;
    return pid;
}

void QuicFecBridgeApp::handleSelfMsg(cMessage* msg)
{
    if (msg == beaconEvent) {
        sendPeriodicBeacon();
        scheduleAt(simTime() + par("beaconInterval"), beaconEvent);
        return;
    }
    if (msg == uploadEvent) {
        reapChildren();
        if (isChildTracked(childPid)) {
            scheduleAt(simTime() + par("pollInterval"), uploadEvent);
            return;
        }
        childPid = -1;
        if (!currentAliasPath.empty()) {
            unlink(currentAliasPath.c_str());
            currentAliasPath.clear();
        }

        const std::string source = inputPathForNode();
        char suffix[48];
        snprintf(suffix, sizeof(suffix), "_tx_%06d.bin", uploadSequence);
        std::string alias = source;
        const auto extension = alias.rfind('.');
        if (extension == std::string::npos) alias += suffix;
        else alias.insert(extension, suffix);
        if (link(source.c_str(), alias.c_str()) < 0)
            throw cRuntimeError("link periodic upload input %s: %s", alias.c_str(), strerror(errno));
        currentAliasPath = alias;
        try {
            childPid = launchChild(false, currentAliasPath, uploadSequence);
        }
        catch (...) {
            unlink(currentAliasPath.c_str());
            currentAliasPath.clear();
            throw;
        }
        ++uploadSequence;
        scheduleAt(simTime() + periodicUploadInterval, uploadEvent);
        return;
    }
    if (msg == pollEvent) {
        pollLocalSocket();
        reapChildren();
        scheduleAt(simTime() + par("pollInterval"), pollEvent);
        return;
    }
    DemoBaseApplLayer::handleSelfMsg(msg);
}

void QuicFecBridgeApp::sendPeriodicBeacon()
{
    auto* beacon = new TraCIDemo11pMessage("PeriodicBeacon");
    populateWSM(beacon);
    beacon->setSenderAddress(myId);
    beacon->setSerial(beaconSeq++);
    sendDown(beacon);
}

void QuicFecBridgeApp::pollLocalSocket()
{
    uint8_t buffer[65536];
    while (true) {
        sockaddr_in peer{};
        socklen_t peerLen = sizeof(peer);
        ssize_t n = recvfrom(bridgeFd, buffer, sizeof(buffer), 0,
                reinterpret_cast<sockaddr*>(&peer), &peerLen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            EV_WARN << "bridge recvfrom: " << strerror(errno) << endl;
            break;
        }
        processLocalDatagram(buffer, static_cast<size_t>(n), peer);
    }
}

void QuicFecBridgeApp::processLocalDatagram(const uint8_t* data, size_t length, const sockaddr_in& peer)
{
    if (length < IPC_HEADER_SIZE || memcmp(data, IPC_MAGIC, sizeof(IPC_MAGIC)) != 0) return;
    const uint8_t type = data[4];
    const uint16_t src = get16(data + 5);
    const uint16_t dst = get16(data + 7);

    if (type == IPC_REGISTER) {
        if ((isRSU && src == RSU_ID) || (!isRSU && src == nodeId)) {
            if (isRSU) { serverPeer = peer; haveServerPeer = true; }
            else { goPeer = peer; haveGoPeer = true; }
            if (isRSU && haveServerPeer && !queuedForServer.empty()) {
                for (const auto& queued : queuedForServer) {
                    sendLocalEnvelope(serverPeer, IPC_DATA, get16(queued.data() + 5), RSU_ID,
                            queued.data() + IPC_HEADER_SIZE, queued.size() - IPC_HEADER_SIZE);
                }
                queuedForServer.clear();
            }
        }
        return;
    }
    if (type != IPC_DATA) return;
    const uint8_t* payload = data + IPC_HEADER_SIZE;
    const size_t payloadLength = length - IPC_HEADER_SIZE;

    if (isRSU) {
        if (src != RSU_ID || dst == RSU_ID) return;
        auto it = vehicleMacs.find(dst);
        if (it == vehicleMacs.end()) {
            EV_WARN << "no learned MAC for vehicle " << dst << "; drop downlink QUIC datagram" << endl;
            return;
        }
        sendRadioDatagram(dst, it->second, payload, payloadLength);
    }
    else {
        if (src != nodeId || dst != RSU_ID || rsuMacAddress == LAddress::L2NULL()) return;
        sendRadioDatagram(RSU_ID, rsuMacAddress, payload, payloadLength);
    }
}

void QuicFecBridgeApp::sendRadioDatagram(int dstNode, LAddress::L2Type dstMac,
        const uint8_t* payload, size_t length)
{
    if (packetsToRadio == 0)
        EV_WARN << "first QUIC WSM from node " << nodeId << " to " << dstNode
                << " mac=" << dstMac << " payload=" << length << "B" << endl;
    auto* packet = new QuicFecDatagram("quic-fec-udp");
    packet->setSrcNode(isRSU ? RSU_ID : nodeId);
    packet->setDstNode(dstNode);
    packet->setPayloadArraySize(static_cast<int>(length));
    for (size_t i = 0; i < length; ++i) packet->setPayload(static_cast<int>(i), payload[i]);
    populateWSM(packet, dstMac);
    // QUIC gives PacketConn the UDP payload. Account for IPv4+UDP (28 bytes)
    // in the WSM airtime; the 802.11p MAC/PHY add their own modeled headers.
    packet->setBitLength(static_cast<int64_t>(length + 28) * 8);
    sendDown(packet);
    ++packetsToRadio;
    bytesToRadio += length;
}

void QuicFecBridgeApp::onWSM(BaseFrame1609_4* frame)
{
    auto* packet = dynamic_cast<QuicFecDatagram*>(frame);
    if (!packet) return;
    const int src = packet->getSrcNode();
    const int dst = packet->getDstNode();
    const size_t length = static_cast<size_t>(packet->getPayloadArraySize());
    std::vector<uint8_t> payload(length);
    for (size_t i = 0; i < length; ++i) payload[i] = packet->getPayload(static_cast<int>(i));
    ++packetsFromRadio;
    bytesFromRadio += length;

    if (isRSU) {
        if (src < 0 || src == RSU_ID || dst != RSU_ID) return;
        if (packetsFromRadio == 1)
            EV_WARN << "RSU received first QUIC WSM from vehicle " << src << endl;
        auto* info = dynamic_cast<PhyToMacControlInfo*>(packet->getControlInfo());
        if (!info) {
            EV_WARN << "uplink WSM missing source MAC control info" << endl;
            return;
        }
        vehicleMacs[src] = info->getSourceAddress();
        if (!haveServerPeer) {
            std::vector<uint8_t> queued(IPC_HEADER_SIZE + length);
            memcpy(queued.data(), IPC_MAGIC, sizeof(IPC_MAGIC));
            queued[4] = IPC_DATA;
            put16(queued.data() + 5, static_cast<uint16_t>(src));
            put16(queued.data() + 7, RSU_ID);
            if (length) memcpy(queued.data() + IPC_HEADER_SIZE, payload.data(), length);
            queuedForServer.push_back(std::move(queued));
            return;
        }
        sendLocalEnvelope(serverPeer, IPC_DATA, static_cast<uint16_t>(src), RSU_ID,
                payload.data(), payload.size());
    }
    else {
        if (src != RSU_ID || dst != nodeId || !haveGoPeer) return;
        if (packetsFromRadio == 1)
            EV_WARN << "vehicle " << nodeId << " received first RSU QUIC WSM" << endl;
        sendLocalEnvelope(goPeer, IPC_DATA, RSU_ID, static_cast<uint16_t>(nodeId),
                payload.data(), payload.size());
    }
}

void QuicFecBridgeApp::sendLocalEnvelope(const sockaddr_in& peer, uint8_t type,
        uint16_t src, uint16_t dst, const uint8_t* payload, size_t length)
{
    std::vector<uint8_t> envelope(IPC_HEADER_SIZE + length);
    memcpy(envelope.data(), IPC_MAGIC, sizeof(IPC_MAGIC));
    envelope[4] = type;
    put16(envelope.data() + 5, src);
    put16(envelope.data() + 7, dst);
    if (length) memcpy(envelope.data() + IPC_HEADER_SIZE, payload, length);
    ssize_t n = sendto(bridgeFd, envelope.data(), envelope.size(), 0,
            reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    if (n < 0 || static_cast<size_t>(n) != envelope.size())
        EV_WARN << "bridge sendto: " << strerror(errno) << endl;
}

void QuicFecBridgeApp::finish()
{
    DemoBaseApplLayer::finish();
    recordScalar("quicfecPacketsToRadio", static_cast<double>(packetsToRadio));
    recordScalar("quicfecPacketsFromRadio", static_cast<double>(packetsFromRadio));
    recordScalar("quicfecBytesToRadio", static_cast<double>(bytesToRadio));
    recordScalar("quicfecBytesFromRadio", static_cast<double>(bytesFromRadio));
    if (isRSU) stopChildren();
}

} // namespace veins_cosim
