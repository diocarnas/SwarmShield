import asyncio, pyshark

asyncio.set_event_loop(asyncio.new_event_loop())
cap = pyshark.LiveCapture(interface="Wi-Fi", bpf_filter="ip", only_summaries=True)
for p in cap.sniff_continuously(packet_count=5):
    print(type(p), getattr(p, "_fields", None))
    print(p)