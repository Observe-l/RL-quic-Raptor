package veins_cosim;

import org.car2x.veins.modules.application.ieee80211p.DemoBaseApplLayer;

simple QuicFecBridgeApp extends DemoBaseApplLayer
{
    parameters:
        @class(veins_cosim::QuicFecBridgeApp);
        bool isRSU = default(false);
        int bridgePortBase = default(41000);
        int rsuBridgePort = default(40999);
        double pollInterval @unit(s) = default(1ms);
        double periodicUploadInterval @unit(s) = default(0s);
        string clientBin = default("");
        string serverBin = default("");
        string clientInputDir = default("");
        string receiveDir = default("");
        string logDir = default("");
        string clientOptions = default("-timeout 120s -connect-timeout 45s -N 32 -K 26 -L 1200 -arq -R0 6 -W 8 -Rstep 4 -max-attempts 5 -ack-every 8");
        string serverOptions = default("-timeout 360s -rx-workers 2 -decode-ddl 25ms");
        bool periodicBeaconing = default(true);
}
