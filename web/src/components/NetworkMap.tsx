import { ArrowRight, HelpCircle, Laptop, Router, ShieldCheck, Smartphone } from "lucide-react";

type ObservedPacket = { source: string; destination: string; protocol: string };

type NetworkMapProps = {
  packets: ObservedPacket[];
  isCapturing: boolean;
  onInspectAddress: (address: string) => void;
};

export function NetworkMap({ packets, isCapturing, onInspectAddress }: NetworkMapProps) {
  const sources = [...new Set(packets.map((packet) => packet.source).filter((value) => value && value !== "—"))].slice(0, 2);
  const destinations = [...new Set(packets.map((packet) => packet.destination).filter((value) => value && value !== "—"))].slice(0, 2);
  const observedCount = new Set(
    packets.flatMap((packet) => [packet.source, packet.destination]).filter((value) => value !== "—"),
  ).size;

  function updateParallax(event: React.PointerEvent<HTMLDivElement>) {
    if (event.pointerType !== "mouse") return;
    const bounds = event.currentTarget.getBoundingClientRect();
    const horizontal = (event.clientX - bounds.left) / bounds.width - 0.5;
    const vertical = (event.clientY - bounds.top) / bounds.height - 0.5;
    event.currentTarget.style.setProperty("--shift-x", `${(horizontal * 9).toFixed(1)}px`);
    event.currentTarget.style.setProperty("--shift-y", `${(vertical * 7).toFixed(1)}px`);
    event.currentTarget.style.setProperty("--counter-x", `${(-horizontal * 5).toFixed(1)}px`);
    event.currentTarget.style.setProperty("--counter-y", `${(-vertical * 4).toFixed(1)}px`);
  }

  function resetParallax(event: React.PointerEvent<HTMLDivElement>) {
    event.currentTarget.style.removeProperty("--shift-x");
    event.currentTarget.style.removeProperty("--shift-y");
    event.currentTarget.style.removeProperty("--counter-x");
    event.currentTarget.style.removeProperty("--counter-y");
  }

  return (
    <section className="network-map card" aria-labelledby="network-map-title">
      <div className="section-head">
        <div>
          <span className="section-kicker">YOUR NETWORK, MADE VISIBLE</span>
          <h2 id="network-map-title">How your traffic travels</h2>
          <p>Messages travel between devices. PocketSniff watches what this network adapter can see{observedCount ? "; select an observed address to inspect its packets" : ""}.</p>
        </div>
        <span className="result-count">{observedCount} addresses seen</span>
      </div>

      <div className={`network-map-art ${isCapturing ? "is-capturing" : ""}`} onPointerMove={updateParallax} onPointerLeave={resetParallax}>
        <div className="map-grid-glow" aria-hidden="true" />
        <div className="map-device router-device">
          <span className="map-device-icon"><Router size={23} /></span>
          <strong>Your network</strong>
          <small>Wi-Fi or Ethernet</small>
          {sources.length > 0 && <button type="button" className="map-address map-address-action" aria-label={`Show packets involving source ${sources[0]}`} onClick={() => onInspectAddress(sources[0])}>{sources[0]}</button>}
        </div>

        <div className="map-connection map-connection-left" aria-hidden="true">
          <span className="map-wire" />
          <span className="map-packet map-packet-one" />
          <span className="map-packet map-packet-two" />
          <ArrowRight className="map-arrow" size={17} />
        </div>

        <div className="map-sensor">
          <div className="sensor-orbit sensor-orbit-one" />
          <div className="sensor-orbit sensor-orbit-two" />
          <span className="map-sensor-icon"><ShieldCheck size={27} /></span>
          <strong>Local sniffer</strong>
          <small>{isCapturing ? "Watching real packets" : "Ready when you are"}</small>
          <span className="sensor-local-label"><i /> Only on this device</span>
        </div>

        <div className="map-connection map-connection-right" aria-hidden="true">
          <span className="map-wire" />
          <span className="map-packet map-packet-one" />
          <span className="map-packet map-packet-two" />
          <ArrowRight className="map-arrow" size={17} />
        </div>

        <div className="map-device destination-device">
          <span className="map-device-icon"><Laptop size={22} /><Smartphone className="map-phone" size={15} /></span>
          <strong>Destinations seen</strong>
          <small>Devices, websites, and apps</small>
          {destinations.length > 0 && <button type="button" className="map-address map-address-action" aria-label={`Show packets involving destination ${destinations[0]}`} onClick={() => onInspectAddress(destinations[0])}>{destinations[0]}</button>}
        </div>
      </div>

      <div className="network-map-legend">
        <span><i className="legend-purple" /> Source: who sent it</span>
        <span><i className="legend-blue" /> Destination: where it went</span>
        <span><ShieldCheck size={14} /> Packet contents stay private</span>
      </div>
      <p className="visibility-note"><HelpCircle size={14} /> What you can see depends on your adapter and its mode. Ordinary Wi-Fi usually shows this computer’s own traffic; monitor mode needs compatible hardware and a driver.</p>
    </section>
  );
}
