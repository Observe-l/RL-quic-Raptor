#pragma once

#include <cstdint>
#include <map>
#include <netinet/in.h>
#include <string>
#include <sys/types.h>
#include <vector>

#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"

namespace veins_cosim {

class QuicFecBridgeApp : public veins::DemoBaseApplLayer {
  protected:
    static constexpr uint16_t RSU_ID = 0xffff;
    static constexpr size_t IPC_HEADER_SIZE = 9;
    static constexpr uint8_t IPC_DATA = 1;
    static constexpr uint8_t IPC_REGISTER = 2;

    int bridgeFd = -1;
    int nodeId = -1;
    bool isRSU = false;
    bool haveGoPeer = false;
    bool haveServerPeer = false;
    int rsuBridgePort = -1;
    int bridgePortBase = -1;
    int pollKind = 0;
    int beaconKind = 0;
    int uploadKind = 0;
    int beaconSeq = 0;
    int uploadSequence = 0;
    double periodicUploadInterval = 0;
    pid_t childPid = -1;
    uint64_t packetsToRadio = 0;
    uint64_t packetsFromRadio = 0;
    uint64_t bytesToRadio = 0;
    uint64_t bytesFromRadio = 0;
    veins::LAddress::L2Type rsuMacAddress = veins::LAddress::L2NULL();
    sockaddr_in goPeer{};
    sockaddr_in serverPeer{};
    omnetpp::cMessage* pollEvent = nullptr;
    omnetpp::cMessage* beaconEvent = nullptr;
    omnetpp::cMessage* uploadEvent = nullptr;
    std::string currentAliasPath;
    std::map<int, veins::LAddress::L2Type> vehicleMacs;
    std::vector<std::vector<uint8_t>> queuedForServer;

    void handleSelfMsg(omnetpp::cMessage* msg) override;
    void onWSM(veins::BaseFrame1609_4* wsm) override;
    void pollLocalSocket();
    void sendPeriodicBeacon();
    void processLocalDatagram(const uint8_t* data, size_t length, const sockaddr_in& peer);
    void sendRadioDatagram(int dstNode, veins::LAddress::L2Type dstMac,
            const uint8_t* payload, size_t length);
    void sendLocalEnvelope(const sockaddr_in& peer, uint8_t type, uint16_t src,
            uint16_t dst, const uint8_t* payload, size_t length);
    bool resolveRsuMac();
    pid_t launchChild(bool server, const std::string& fileOverride = "", int transferSequence = -1);
    std::string inputPathForNode() const;

  public:
    ~QuicFecBridgeApp() override;
    void initialize(int stage) override;
    void finish() override;
};

} // namespace veins_cosim
