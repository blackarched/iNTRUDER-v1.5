document.addEventListener("DOMContentLoaded", () => {
  const panels = document.querySelectorAll(".panel");
  const outputs = document.querySelectorAll(".output");

  function showOutput(id, content, isError = false) {
    const output = document.getElementById(id);
    output.textContent = content;
    output.style.color = isError ? "#ff6b6b" : "#0f0";
  }

  async function postData(url, data = {}) {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      return await response.json();
    } catch (err) {
      return { status: "error", message: err.message };
    }
  }

  document.getElementById("start-mon-btn").addEventListener("click", async () => {
    const res = await postData("/api/start-monitor");
    showOutput("start-mon-output", res.stdout || res.message, res.status !== "success");
  });

  document.getElementById("scan-handshake-btn").addEventListener("click", async () => {
    const iface = document.getElementById("capture-iface").value;
    const ssid = document.getElementById("capture-ssid").value;
    // Basic validation: ensure iface is provided
    if (!iface) {
      showOutput("scan-handshake-output", "Error: Interface is required.", true);
      return;
    }
    const res = await postData("/api/scan-handshake", { iface, ssid });
    showOutput("scan-handshake-output", JSON.stringify(res, null, 2), res.status !== "success");
  });

  document.getElementById("log-sniffer-btn").addEventListener("click", async () => {
    const res = await postData("/api/scan-networks");
    showOutput("log-sniffer-output", JSON.stringify(res, null, 2), res.status !== "success");
  });

  document.getElementById("deauth-btn").addEventListener("click", async () => {
    const bssid = document.getElementById("deauth-bssid").value;
    const client = document.getElementById("deauth-client").value;
    const countInput = document.getElementById("deauth-count").value;
    const count = countInput ? parseInt(countInput) : 10;
    const iface = document.getElementById("deauth-iface").value || "wlan0mon";
    const res = await postData("/api/deauth", { bssid, client, interface: iface, count: count });
    showOutput("deauth-output", JSON.stringify(res, null, 2), res.status !== "success");
  });

  document.getElementById("crack-btn").addEventListener("click", async () => {
    const handshake = document.getElementById("crack-handshake").value;
    const wordlist = document.getElementById("crack-wordlist").value;
    const res = await postData("/api/crack", { handshake, wordlist });
    showOutput("crack-output", JSON.stringify(res, null, 2), res.status !== "success");
  });

  panels.forEach(panel => {
    const btn = panel.querySelector("button");
    if (btn) btn.click();
  });
});