#!/usr/bin/env python3
# ns-3.46 / cppyy Python bindings
import sys, argparse
import cppyy
from ns import ns

def main():
    # ---------- CLI ----------
    ap = argparse.ArgumentParser(description="P2P + TapBridge for external QUIC app")
    ap.add_argument("--tapName", type=str, default="tap-left", help="host TAP iface name")
    ap.add_argument("--dataRate", type=str, default="100Mbps")
    ap.add_argument("--delay", type=str, default="10ms")
    ap.add_argument("--mtu", type=int, default=1500)
    ap.add_argument("--loss", type=float, default=0.0, help="packet loss rate in [0,1]")
    ap.add_argument("--stop", type=float, default=60.0, help="sim time (s)")
    args = ap.parse_args()

    # ---------- Nodes & P2P ----------
    nodes = ns.NodeContainer()
    nodes.Create(2)

    p2p = ns.PointToPointHelper()
    p2p.SetDeviceAttribute("DataRate", ns.StringValue(args.dataRate))
    p2p.SetChannelAttribute("Delay", ns.StringValue(args.delay))
    devices = p2p.Install(nodes)

    # ---------- 给设备挂误码模型（按“方法优先”的接口） ----------
    if args.loss > 0.0:
        em0 = ns.RateErrorModel()
        em1 = ns.RateErrorModel()
        # 首选：使用方法接口（ns-3.46 常见）
        if hasattr(em0, "SetRate") and hasattr(ns.RateErrorModel, "ERROR_UNIT_PACKET"):
            em0.SetRate(float(args.loss)); em0.SetUnit(ns.RateErrorModel.ERROR_UNIT_PACKET)
            em1.SetRate(float(args.loss)); em1.SetUnit(ns.RateErrorModel.ERROR_UNIT_PACKET)
        else:
            # 兜底：用属性名（若你的构建暴露 Attribute 接口）
            if hasattr(em0, "SetAttribute") and hasattr(ns, "EnumValue"):
                em0.SetAttribute("Unit", ns.EnumValue(ns.RateErrorModel.ERROR_UNIT_PACKET))
                em0.SetAttribute("ErrorRate", ns.DoubleValue(float(args.loss)))
                em1.SetAttribute("Unit", ns.EnumValue(ns.RateErrorModel.ERROR_UNIT_PACKET))
                em1.SetAttribute("ErrorRate", ns.DoubleValue(float(args.loss)))
            else:
                print("[warn] RateErrorModel API not found; skipping loss model.")
                em0 = None; em1 = None

        if em0 and em1:
            devices.Get(0).SetAttribute("ReceiveErrorModel", ns.PointerValue(em0))
            devices.Get(1).SetAttribute("ReceiveErrorModel", ns.PointerValue(em1))

    # ---------- Internet Stack & IPv4 ----------
    internet = ns.InternetStackHelper()
    internet.Install(nodes)

    ipv4 = ns.Ipv4AddressHelper()
    ipv4.SetBase(ns.Ipv4Address("10.0.0.0"), ns.Ipv4Mask("255.255.255.0"))
    ifaces = ipv4.Assign(devices)

    # 可选：设置 MTU（对应 NetDevice 的属性名是 "Mtu"）
    for i in range(devices.GetN()):
        if hasattr(devices.Get(i), "SetMtu"):
            devices.Get(i).SetMtu(args.mtu)
        else:
            devices.Get(i).SetAttribute("Mtu", ns.UintegerValue(args.mtu))

    # 静态路由（在这个两节点拓扑里其实不需要；加上也无妨）
    ns.Ipv4GlobalRoutingHelper.PopulateRoutingTables()

    # ---------- TapBridge ----------
    # 这里使用 ConfigureLocal：在 host 上创建 tap，并与 node0 的 NetDevice 桥接
    tap = ns.TapBridgeHelper()
    tap.SetAttribute("Mode", ns.StringValue("ConfigureLocal"))
    tap.SetAttribute("DeviceName", ns.StringValue(args.tapName))
    tap.Install(nodes.Get(0), devices.Get(0))

    # ---------- 日志/停止 ----------
    ns.Simulator.Stop(ns.Seconds(args.stop))
    print(f"[ns3] running {args.stop}s; link={args.dataRate}/{args.delay}, loss={args.loss}, tap={args.tapName}")
    ns.Simulator.Run()
    ns.Simulator.Destroy()
    print("[ns3] done.")

if __name__ == "__main__":
    main()
