import { expect, test, type Page, type Route } from "@playwright/test";

const API = "http://127.0.0.1:8000";
const samplePacket = {
  id: "packet-001",
  session_id: "session-abc123",
  time: "2026-11-01T12:00:00+00:00",
  protocol: "TCP",
  source: "192.0.2.10",
  destination: "198.51.100.20",
  source_mac: "02:00:00:00:00:10",
  destination_mac: "02:00:00:00:00:20",
  source_port: 43123,
  destination_port: 443,
  transport: "TCP",
  tcp_flags: "S",
  ttl: 61,
  length: 74,
  original_length: 74,
  info: "TCP packet",
  interface: "Ethernet",
  capture_backend: "scapy-live",
};

type MockOptions = {
  online?: boolean;
  captureState?: string;
  captureRequests?: Record<string, unknown>[];
  reportRequests?: string[];
  uploadRequests?: string[];
  packetRequests?: URL[];
  loopbackPermission?: "prompt" | "granted" | "denied";
  healthRequests?: number[];
  healthSequence?: boolean[];
  overviewDelayMs?: number;
  statisticsPackets?: number;
  agentVersion?: string;
};

async function mockLocalAgent(page: Page, options: MockOptions = {}) {
  let started = false;
  const {
    online = true,
    captureState = "idle",
    captureRequests = [],
    reportRequests = [],
    uploadRequests = [],
    packetRequests = [],
    loopbackPermission = "granted",
    healthRequests = [],
    healthSequence = [],
    overviewDelayMs = 0,
    statisticsPackets = 1,
    agentVersion = "0.2.2",
  } = options;

  await page.addInitScript((permissionState) => {
    const originalQuery = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = ((descriptor: PermissionDescriptor) => {
      if ((descriptor.name as string) === "loopback-network") {
        return Promise.resolve({ state: permissionState, onchange: null, addEventListener() {}, removeEventListener() {} } as unknown as PermissionStatus);
      }
      return originalQuery(descriptor);
    }) as typeof navigator.permissions.query;
  }, loopbackPermission);

  await page.route(`${API}/**`, async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === "/api/health") {
      healthRequests.push(Date.now());
      const healthy = healthSequence.length ? healthSequence.shift() ?? online : online;
      return route.fulfill({ status: healthy ? 200 : 503, json: healthy ? { status: "ok", version: agentVersion } : { detail: "Sensor not running" } });
    }
    if (path === "/api/interfaces") {
      return route.fulfill({ json: { interfaces: [{ name: "\\Device\\NPF_{TEST}", description: "Intel Wi-Fi 6 Adapter", friendly_name: "Wi-Fi", ips: ["192.0.2.10"], mac: "02:00:00:00:00:10", status: "Up", capture_candidate: true, recommended: true }] } });
    }
    if (path === "/api/overview") {
      if (overviewDelayMs) await new Promise((resolve) => setTimeout(resolve, overviewDelayMs));
      return route.fulfill({ json: { total_packets: 1, total_bytes: 74, active_sessions: 1, protocols: { TCP: 1 }, top_talkers: [["192.0.2.10", 1]] } });
    }
    if (path === "/api/packets") {
      packetRequests.push(url);
      const matches = url.searchParams.get("protocol") && url.searchParams.get("protocol") !== "TCP" ? [] : [samplePacket];
      const offset = Number(url.searchParams.get("offset") || 0);
      return route.fulfill({ json: { total: matches.length, count: matches.length, limit: 50, offset, packets: matches.slice(offset, offset + 50) } });
    }
    if (path === "/api/sessions") {
      return route.fulfill({ json: [{ session_id: "session-abc123", packet_count: 1, first_packet_at: samplePacket.time, last_packet_at: samplePacket.time }] });
    }
    if (path === "/api/alerts") {
      return route.fulfill({ json: { alerts: [{ id: "alert-1", session_id: "session-abc123", rule_id: "arp-address-conflict", severity: "warning", message: "An address was claimed by two devices", time: samplePacket.time, evidence: { ip_address: "192.0.2.10" } }] } });
    }
    if (path === "/api/statistics") {
      return route.fulfill({ json: { total_packets: statisticsPackets, total_bytes: 74, packets_per_sec: 5, protocols: [["TCP", statisticsPackets]], top_talkers: [["192.0.2.10", statisticsPackets]] } });
    }
    if (path === "/api/capture/status") {
      const state = started ? "running" : captureState;
      return route.fulfill({ json: { state, session_id: state === "running" ? "session-abc123" : null, source: "interface", interface: "Wi-Fi", started_at: samplePacket.time, result: null, error: null } });
    }
    if (path === "/api/capture/upload") {
      uploadRequests.push(route.request().postDataBuffer()?.toString("latin1") || "");
      return route.fulfill({ json: { upload_id: "upload-local-123", filename: "my-capture.pcap", size: 40 } });
    }
    if (path === "/api/capture/start") {
      captureRequests.push(route.request().postDataJSON() as Record<string, unknown>);
      started = true;
      return route.fulfill({ json: { state: "running", session_id: "session-abc123", source: "interface", interface: "Wi-Fi", started_at: samplePacket.time, result: null, error: null } });
    }
    if (path === "/api/capture/stop") {
      return route.fulfill({ json: { state: "stopping", stop_requested: true } });
    }
    if (path === "/api/sessions/session-abc123/report") {
      reportRequests.push(url.searchParams.get("format") || "csv");
      const format = url.searchParams.get("format");
      return route.fulfill({ status: 200, contentType: format === "pdf" ? "application/pdf" : "text/csv", body: format === "pdf" ? "%PDF-1.4 local report" : "session_id,packet_count\nsession-abc123,1" });
    }
    return route.fulfill({ status: 404, json: { detail: `Unhandled local request: ${path}` } });
  });
}

test("offline landing explains setup without asking visitors to run project scripts", async ({ page }) => {
  await mockLocalAgent(page, { online: false });
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Your private network view is one minute away." })).toBeVisible();
  await expect(page.getByRole("link", { name: "Download the Windows capture sensor" })).toHaveAttribute("href", /releases\/latest\/download/);
  await expect(page.getByRole("link", { name: "Get Npcap" })).toBeVisible();
  await expect(page.getByText("run-local.ps1")).toHaveCount(0);
  await expect(page.getByText("Packet data is never sent to this website.")).toBeVisible();
});

test("privacy guidance stays visible and explains local handling and authorized use", async ({ page }) => {
  await mockLocalAgent(page);
  await page.goto("/");

  const notice = page.locator(".privacy-notice");
  await expect(notice.getByText("Privacy & responsible use")).toBeVisible();
  await notice.locator("summary").click();
  await expect(notice).toContainText("explicitly authorized to inspect");
  await expect(notice).toContainText("Captures can contain sensitive information");
  await expect(notice).toContainText("sent to the sensor on this same computer only");

  await notice.getByRole("button", { name: "Open setup & privacy" }).click();
  await expect(page.getByRole("heading", { name: "Sensor setup & privacy" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Capture compatibility" })).toBeVisible();
  await expect(page.getByText("Live BLE scanning is not included in the current Windows sensor.")).toBeVisible();
});

test("local sensor waits for an explicit connection when loopback permission is pending", async ({ page }) => {
  const requests: number[] = [];
  await mockLocalAgent(page, { healthRequests: requests, loopbackPermission: "prompt" });
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Connect to this computer" })).toBeVisible();
  await page.waitForTimeout(150);
  expect(requests).toHaveLength(0);

  await page.getByRole("button", { name: "Connect to this computer" }).click();
  await expect.poll(() => requests.length).toBeGreaterThan(0);
});

test("a single missed health check does not drop an established sensor connection", async ({ page }) => {
  const requests: number[] = [];
  await mockLocalAgent(page, { healthRequests: requests, healthSequence: [true, false, true] });
  await page.goto("/");
  await expect(page.getByText("SENSOR READY", { exact: true })).toBeVisible();
  await expect.poll(() => requests.length, { timeout: 8000 }).toBeGreaterThanOrEqual(2);
  await expect(page.getByText("SENSOR READY", { exact: true })).toBeVisible();
  await expect(page.getByText("Your sensor is connected on this computer.")).toBeVisible();
});

test("live statistics update while the historical summary is still loading", async ({ page }) => {
  await mockLocalAgent(page, { overviewDelayMs: 2500, statisticsPackets: 321 });
  await page.goto("/");
  await expect(page.getByText("321", { exact: true })).toBeVisible({ timeout: 2000 });
});

test("the current sensor version stays connected while offering the optimized update", async ({ page }) => {
  await mockLocalAgent(page, { agentVersion: "0.2.1", statisticsPackets: 321 });
  await page.goto("/");
  await expect(page.getByText("SENSOR READY", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Network summary" }).getByText("321", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Update sensor for faster packet history" })).toHaveAttribute("href", /releases\/latest\/download/);
});

test("overview explains real activity with rate and an address diagram", async ({ page }) => {
  await mockLocalAgent(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Your network, at a glance." })).toBeVisible();
  await expect(page.getByText("Packets per second")).toBeVisible();
  await expect(page.getByText("5.0", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "How your traffic travels" })).toBeVisible();
  await expect(page.getByText("192.0.2.10").first()).toBeVisible();
  await expect(page.getByText("Packet data is never sent to this website.")).toHaveCount(0);
  await page.screenshot({ path: "test-results/dashboard-review.png", fullPage: true });
});

test("selecting an observed map address opens packets filtered to that address", async ({ page }) => {
  await mockLocalAgent(page);
  await page.goto("/");

  await page.getByRole("button", { name: "Show packets involving source 192.0.2.10" }).click();

  await expect(page.getByRole("heading", { name: "Explore packet details" })).toBeVisible();
  await expect(page.getByLabel("Filter by exact address")).toHaveValue("192.0.2.10");
  await expect(page.locator("tbody")).toContainText("198.51.100.20");
});

test("live capture sends selected adapters, BPF and local allowlists to the sensor", async ({ page }) => {
  const requests: Record<string, unknown>[] = [];
  await mockLocalAgent(page, { captureRequests: requests });
  await page.goto("/");

  await page.getByRole("textbox", { name: "OPTIONAL: NARROW WHAT YOU WATCH" }).fill("tcp port 443");
  await page.getByRole("button", { name: "Start watching" }).click();

  await expect.poll(() => requests.length).toBe(1);
  expect(requests[0]).toMatchObject({ mode: "interface", interfaces: ["\\Device\\NPF_{TEST}"], bpf_filter: "tcp port 443" });
  await expect(page.getByRole("button", { name: "Stop watching" })).toBeVisible();
});

test("packet filters use server-side time, session and protocol search, and rows open safe details", async ({ page }) => {
  const requests: URL[] = [];
  await mockLocalAgent(page, { packetRequests: requests });
  await page.goto("/");
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: /^Packets/ }).click();
  await page.getByLabel("Filter by protocol").selectOption("TCP");
  await page.getByLabel("Filter by capture session").selectOption("session-abc123");
  await page.getByLabel("Start time").fill("2026-11-01T11:00");
  await page.getByLabel("End time").fill("2026-11-01T13:00");
  await page.getByLabel("Filter by exact address").fill("192.0.2.10");
  await expect.poll(() => requests.some((url) => url.searchParams.has("address"))).toBe(true);
  const filtered = requests.find((url) => url.searchParams.has("address"));
  expect(filtered?.searchParams.get("protocol")).toBe("TCP");
  expect(filtered?.searchParams.get("session_id")).toBe("session-abc123");
  expect(filtered?.searchParams.get("address")).toBe("192.0.2.10");

  await expect(page.getByText(":43123", { exact: true })).toBeVisible();
  await expect(page.getByText(":443", { exact: true })).toBeVisible();
  await page.getByRole("row", { name: /Inspect TCP packet/ }).click();
  await expect(page.getByRole("heading", { name: "A closer look at one message" })).toBeVisible();
  await expect(page.getByText("443", { exact: true })).toBeVisible();
  await expect(page.getByText("02:00:00:00:00:10", { exact: true })).toBeVisible();
  await expect(page.getByText("Raw packet contents are never shown in this dashboard.")).toBeVisible();
});

test("PCAP replay uses a real file picker and stages the file only on the local agent", async ({ page }) => {
  const uploads: string[] = [];
  const starts: Record<string, unknown>[] = [];
  const externalPosts: string[] = [];
  await mockLocalAgent(page, { uploadRequests: uploads, captureRequests: starts });
  page.on("request", (request) => {
    if (request.method() === "POST" && !request.url().startsWith(API)) externalPosts.push(request.url());
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Open a capture file" }).click();
  await page.locator('input[type="file"]').setInputFiles({
    name: "my-capture.pcap",
    mimeType: "application/vnd.tcpdump.pcap",
    buffer: Buffer.from([0xd4, 0xc3, 0xb2, 0xa1, 0x00]),
  });
  await expect(page.locator(".pcap-dropzone")).toContainText("my-capture.pcap");
  await page.getByRole("button", { name: "Replay this file" }).click();

  await expect.poll(() => uploads.length).toBe(1);
  await expect.poll(() => starts.length).toBe(1);
  expect(starts[0]).toMatchObject({ mode: "pcap", upload_id: "upload-local-123" });
  expect(externalPosts).toEqual([]);
});

test("session reports download as CSV and PDF from local storage", async ({ page }) => {
  const formats: string[] = [];
  await mockLocalAgent(page, { reportRequests: formats });
  await page.goto("/");
  await page.getByRole("button", { name: "Sessions", exact: true }).click();

  const csvDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "CSV", exact: true }).click();
  expect((await csvDownload).suggestedFilename()).toBe("pocket-packet-sniffer-session.csv");
  const pdfDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "PDF", exact: true }).click();
  expect((await pdfDownload).suggestedFilename()).toBe("pocket-packet-sniffer-session.pdf");
  expect(formats).toEqual(["csv", "pdf"]);
});

test("mobile dashboard fits a phone viewport", async ({ page }) => {
  await mockLocalAgent(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Your network, at a glance." })).toBeVisible();
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    page: document.documentElement.scrollWidth,
  }));
  expect(dimensions.page).toBeLessThanOrEqual(dimensions.viewport + 1);
});
