"""Quick reference for the separate QUIC-FEC device launchers.

Use the dedicated scripts below on two different devices:
- receiver machine: python quicfec_device_server.py ...
- sender machine:   python quicfec_device_client.py ...
"""

from __future__ import annotations


def main() -> None:
    print("Server example:")
    print(
        "python quicfec_device_server.py --build --addr 0.0.0.0:25569 "
        "--out data/receive.bin"
    )
    print()
    print("Client example:")
    print(
        "python quicfec_device_client.py --build --server 192.168.1.10 "
        "--port 25569 --in data/send.bin --K 26 --R0 6 --Rstep 4 --ddl-ms 25"
    )


if __name__ == "__main__":
    main()
