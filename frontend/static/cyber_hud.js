document.addEventListener('DOMContentLoaded', function () {
  const matrixRain = document.getElementById('matrixRain');
  const chars =
    '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';

  function createMatrixRain() {
    if (!matrixRain) return;
    const columns = Math.floor(window.innerWidth / 20);
    let html = '';

    for (let i = 0; i < columns; i++) {
      const speed = 50 + Math.random() * 50;
      const delay = Math.random() * 5;
      const length = 10 + Math.floor(Math.random() * 20);

      html += `<div class="absolute top-0 text-green-400 text-xs" style="left: ${i *
        20}px; animation: matrixRain ${speed}s ${delay}s linear infinite;">`;

      for (let j = 0; j < length; j++) {
        const char = chars[Math.floor(Math.random() * chars.length)];
        const opacity = j === length - 1 ? 1 : j / length;
        html += `<div style="opacity: ${opacity};">${char}</div>`;
      }
      html += `</div>`;
    }
    matrixRain.innerHTML = html;

    if (!document.getElementById('matrixRainStyle')) {
      const style = document.createElement('style');
      style.id = 'matrixRainStyle';
      style.innerHTML = `
        @keyframes matrixRain {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }
      `;
      document.head.appendChild(style);
    }
  }

  if (matrixRain) {
    createMatrixRain();
    window.addEventListener('resize', createMatrixRain);
  }

  let analyticsChart, handshakeChart;

  const ctxAnalytics = document.getElementById('networkAnalyticsChart');
  if (ctxAnalytics) {
    analyticsChart = new Chart(ctxAnalytics.getContext('2d'), {
      type: 'line',
      data: {
        labels: [], // Expect this to be populated by socket.io or API
        datasets: [
          {
            label: 'Active Networks',
            data: [], // Expect this to be populated by socket.io or API
            borderColor: '#00ff88',
            backgroundColor: 'rgba(0,255,136,0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
          },
          {
            label: 'Handshake Rate', // e.g. handshakes per minute
            data: [], // Expect this to be populated by socket.io or API
            borderColor: '#00a8ff',
            backgroundColor: 'rgba(0,168,255,0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: true, labels: { color: '#e0f7fa'} } },
        scales: {
          y: { beginAtZero: true, grid: { color: 'rgba(255, 255, 255, 0.1)' }, ticks: { color: '#e0f7fa'} },
          x: { grid: { color: 'rgba(255, 255, 255, 0.1)' }, ticks: { color: '#e0f7fa'} }
        }
      }
    });
  }

  const ctxHandshake = document.getElementById('handshakeChart');
  if (ctxHandshake) {
    handshakeChart = new Chart(ctxHandshake.getContext('2d'), {
      type: 'bar',
      data: {
        labels: [], // Expect this to be populated by API data (e.g. time labels)
        datasets: [
          {
            label: 'Handshakes Captured',
            data: [], // Expect this to be populated by API data
            backgroundColor: 'rgba(0, 255, 136, 0.5)',
            borderColor: '#00ff88',
            borderWidth: 1
          },
          {
            label: 'Deauth Packets Sent',
            data: [], // Expect this to be populated by API data
            backgroundColor: 'rgba(0, 168, 255, 0.5)',
            borderColor: '#00a8ff',
            borderWidth: 1
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: true, labels: {color: '#e0f7fa'} } },
        scales: {
          y: { beginAtZero: true, grid: { color: 'rgba(255, 255, 255, 0.1)' }, ticks: { color: '#e0f7fa'} },
          x: { grid: { color: 'rgba(255, 255, 255, 0.1)' }, ticks: { color: '#e0f7fa'} }
        }
      }
    });
  }

  try {
    const socket = io(); // Assumes server provides the /socket.io/socket.io.js script
    socket.on('network-stats', (data) => { // For real-time network analytics chart
      if (!analyticsChart || !data) return;

      const now = data.timestamp || new Date().toLocaleTimeString(); // Use timestamp from data if available

      if (analyticsChart.data.labels.length > 20) { // Keep chart history limited
        analyticsChart.data.labels.shift();
        analyticsChart.data.datasets.forEach(dataset => dataset.data.shift());
      }

      analyticsChart.data.labels.push(now);
      // Assuming data keys like 'activeNetworks' and 'handshakeRate' come from socket event
      analyticsChart.data.datasets[0].data.push(data.activeNetworks || 0);
      analyticsChart.data.datasets[1].data.push(data.handshakeRate || 0);
      analyticsChart.update();
    });

    socket.on('handshake-update', (data) => {
        // TODO: Implement handshake-update handler based on actual backend data structure.
        // This is a stub and needs to be updated to correctly process and display handshake data.
        // Example: data might contain { timestamp: 'HH:MM', bssid: 'AA:BB:CC:DD:EE:FF', station: '11:22:33:44:55:66', type: 'WPA2 (4-way)' }
        console.warn("[Socket.IO STUB] 'handshake-update' received. Data:", data);
        appendToTerminal(`[Socket.IO STUB] Handshake data received (see console for full object): BSSID ${data.bssid || 'N/A'}, Station: ${data.station || 'N/A'}`);
        if (!handshakeChart || !data) return;
        // Actual chart update logic will depend on how you want to visualize this.
        // For instance, you might increment a counter for a specific BSSID on the chart.
    });

  } catch (e) {
    console.warn("Socket.IO not available or failed to connect. Real-time chart updates might be affected.", e);
  }

  async function postData(url, data = {}) {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (!response.ok) {
          const errorText = await response.text();
          return { status: "error", message: `HTTP error ${response.status}: ${errorText || response.statusText}` };
      }
      return await response.json();
    } catch (err) {
      console.error(`Error in postData for ${url}:`, err);
      return { status: "error", message: err.message || "Network error or server unreachable" };
    }
  }

  async function startMonitorMode(iface = "wlan0mon") {
    return await postData("/api/start-monitor", { interface: iface });
  }

  async function startNetworkScan(duration = "30s") {
    return await postData("/api/scan-handshake", { duration: duration });
  }

  async function startHandshakeCapture(bssid, channel = "", ssid = "") {
    // Corrected API endpoint for handshake capture.
    return await postData("/api/handshake/start", { bssid, channel, ssid });
  }

  async function startDeauthAttack(bssid, client_mac = "", count = "100", iface = "wlan0mon") {
    return await postData("/api/deauth/start", { target_bssid: bssid, client_mac: client_mac, count: count, iface: iface });
  }

  async function startCrackHandshake(cap_file, wordlist_file) {
    return await postData("/api/crack", { handshake: cap_file, wordlist: wordlist_file });
  }

  const terminalInput = document.getElementById('terminalInput');
  const terminalOutput = document.getElementById('terminalOutput');

  function appendToTerminal(htmlContent, isCommand = false) {
    if (!terminalOutput || !terminalInput) return;
    const promptElement = terminalOutput.querySelector('.flex.items-center:has(input#terminalInput)');
    const newLine = document.createElement('div');
    newLine.className = 'mb-2';
    if (isCommand) {
      newLine.innerHTML = `<span class="text-white">root@intruder:~# ${htmlContent.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</span>`; // Basic escaping for command display
    } else {
      newLine.innerHTML = htmlContent; // Assumes internal messages are safe or pre-sanitized
    }
    if (promptElement) {
        terminalOutput.insertBefore(newLine, promptElement);
    } else {
        terminalOutput.appendChild(newLine);
    }
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
  }

  if (terminalInput) {
    terminalInput.addEventListener('keypress', async function (e) {
      if (e.key === 'Enter') {
        const commandFull = terminalInput.value.trim();
        terminalInput.value = '';
        appendToTerminal(commandFull, true);

        const [command, ...args] = commandFull.split(/\s+/);
        let response;
        let userMessage = '';

        try {
            switch (command) {
                case 'help':
                case '':
                    userMessage = `Available commands:<br>
                                monitor [interface] - Activate Monitor Mode (default: wlan0mon)<br>
                                scan [duration] - Run network scan (default: 30s)<br>
                                handshake &lt;bssid&gt; [channel] [ssid] - Start handshake capture<br>
                                deauth &lt;bssid&gt; [client_mac] [count] [interface] - Launch deauth attack<br>
                                crack &lt;cap_file&gt; &lt;wordlist_file&gt; - Crack captured handshake<br>
                                clear - Clear terminal<br>
                                help - Show this help message`;
                    appendToTerminal(userMessage);
                    break;
                case 'monitor':
                    response = await startMonitorMode(args[0]);
                    if (response.status === 'success' && response.monitor_interface) { // Check for monitor_interface in response
                        const newInterface = response.monitor_interface;
                        userMessage = `Monitor mode successfully started on ${newInterface}.`;
                        updateTopNavInterface(newInterface); // Update top nav display
                        const monitorCard = document.querySelector('.hacker-card[data-action="monitor"]');
                        if (monitorCard) {
                            // These are stubbed UI elements, actual state change logic will be more complex
                            // monitorCard.querySelector('.text-xs.text-gray-400').textContent = `Interface: ${newInterface}`;
                            // monitorCard.querySelector('.text-xs.bg-green-500\\/20').textContent = 'Active';
                            // monitorCard.querySelector('.w-3.h-3.rounded-full').classList.add('bg-green-500', 'animate-pulse');
                            // monitorCard.querySelector('.text-xs.text-gray-400').textContent = `Interface: ${response.data?.interface || args[0] || 'wlan0mon'}`;
                            appendToTerminal("UI card for Monitor Mode is a STUB and not dynamically updated yet.");
                        }
                    } else {
                        userMessage = `Error starting monitor mode: ${response.message || 'Unknown error'}`;
                        console.error("Monitor mode error response:", response);
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: <pre>${JSON.stringify(response, null, 2)}</pre>`);
                    break;
                case 'scan':
                    appendToTerminal("Starting network scan...");
                    response = await startNetworkScan(args[0]);
                    if (response.status === 'success' && response.data) {
                        userMessage = `Network scan completed. Found ${response.data.networks_found_count || 0} networks.`;
                        // TODO: Make UI updates more robust
                        // const networksFoundCard = document.querySelector('.glass-effect.rounded-xl.p-6:nth-child(1) h3');
                        // if (networksFoundCard) networksFoundCard.textContent = response.data.networks_found_count || '0';
                        // const scanCard = document.querySelector('.hacker-card[data-action="scan"]');
                        // if (scanCard) {
                        //      scanCard.querySelector('.text-xs.bg-blue-500\\/20').textContent = 'Completed';
                        //      scanCard.querySelector('.text-xs.text-gray-400').textContent = `Last: Just now`;
                        // }
                        appendToTerminal("Stats cards and Scan Control Panel card are STUBS and not dynamically updated yet.");

                        if(response.data.scan_results && Array.isArray(response.data.scan_results)) {
                            appendToTerminal(`Top Networks: <pre>${JSON.stringify(response.data.scan_results.slice(0,5), null, 2)}</pre>... (showing first 5)`);
                        }
                    } else {
                        userMessage = `Error during network scan: ${response.message || 'Unknown error'}`;
                        console.error("Network scan error response:", response);
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: <pre>${JSON.stringify(response, null, 2)}</pre>`);
                    break;
                case 'handshake':
                    if (args.length < 1) {
                        appendToTerminal("Usage: handshake &lt;bssid&gt; [channel] [ssid]");
                        break;
                    }
                    appendToTerminal(`Starting handshake capture for BSSID ${args[0]}...`);
                    response = await startHandshakeCapture(args[0], args[1], args[2]);
                    if (response.status === 'success' || response.status === 'success_with_errors') {
                        userMessage = `Handshake capture process started for BSSID ${args[0]}. File: ${response.file || 'N/A'}. Message: ${response.message}`;
                        const handshakeCtrlCard = document.querySelector('.hacker-card[data-action="handshake"]');
                        if (handshakeCtrlCard) {
                            handshakeCtrlCard.querySelector('.text-xs.bg-yellow-500\\/20').textContent = 'Running';
                            const stopBtn = document.getElementById('stopHandshakeBtn');
                            if(stopBtn) stopBtn.disabled = false;
                        }
                        updateHandshakesCapturedStats(); // Update stats after a capture attempt
                    } else {
                        userMessage = `Error starting handshake capture: ${response.message || 'Unknown error'}`;
                        console.error("Handshake capture error response:", response);
                        const handshakeCtrlCard = document.querySelector('.hacker-card[data-action="handshake"]');
                        if (handshakeCtrlCard) {
                             handshakeCtrlCard.querySelector('.text-xs.bg-yellow-500\\/20').textContent = 'Error';
                        }
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: <pre>${JSON.stringify(response, null, 2)}</pre>`);
                    break;
                case 'deauth':
                    if (args.length < 1 || args[0].toUpperCase() === "YOUR_BSSID_HERE") {
                        appendToTerminal("Usage: deauth &lt;target_bssid&gt; [client_mac] [count] [interface]<br>Replace YOUR_BSSID_HERE with an actual BSSID.");
                        break;
                    }
                    appendToTerminal(`Starting deauth attack on BSSID ${args[0]}...`);
                    response = await startDeauthAttack(args[0], args[1], args[2], args[3]); // args are target_bssid, client_mac, count, iface
                    if (response.status === 'success') { // Simplified check, specific data structure might vary
                        userMessage = `Deauth attack command sent for ${args[0]}. Status: ${response.message || 'Completed. Check logs.'}`;
                        // TODO: Make UI updates more robust
                        // const deauthAttacksCard = document.querySelector('.glass-effect.rounded-xl.p-6:nth-child(3) h3');
                        // if (deauthAttacksCard && response.data.deauth_attacks_count) deauthAttacksCard.textContent = response.data.deauth_attacks_count;
                        // const deauthCtrlCard = document.querySelector('.hacker-card[data-action="deauth"]');
                        // if(deauthCtrlCard) {
                        //     deauthCtrlCard.querySelector('.text-xs.bg-red-500\\/20').textContent = 'Finished'; // Or based on actual status
                        // }
                        appendToTerminal("Stats cards and Deauth Control Panel card are STUBS and not dynamically updated yet.");
                    } else {
                        userMessage = `Error during deauth attack: ${response.message || 'Unknown error'}`;
                        console.error("Deauth attack error response:", response);
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: <pre>${JSON.stringify(response, null, 2)}</pre>`);
                    break;
                case 'crack':
                    if (args.length < 2) {
                        appendToTerminal("Usage: crack &lt;cap_file&gt; &lt;wordlist_file&gt;");
                        break;
                    }
                    appendToTerminal(`Starting handshake cracking for ${args[0]}...`);
                    response = await startCrackHandshake(args[0], args[1]);
                     if (response.status === 'success' && response.data) {
                        userMessage = `Cracking session for ${args[0]} status: ${response.message || 'Completed'}.`;
                        if(response.data.password_found && response.data.password) { // Check if password field exists and is non-empty
                             userMessage += ` Password found: <span class='text-green-400 font-bold'>${response.data.password.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</span>`;
                        } else if (response.data.password_found === false) { // Explicitly not found
                             userMessage += " Password not found.";
                        }
                        // TODO: Make UI updates more robust
                        // const crackingSessionsCard = document.querySelector('.glass-effect.rounded-xl.p-6:nth-child(4) h3');
                        // if(crackingSessionsCard && response.data.cracking_sessions_count) crackingSessionsCard.textContent = response.data.cracking_sessions_count;
                        appendToTerminal("Stats cards for Cracking Sessions is a STUB and not dynamically updated yet.");
                    } else {
                        userMessage = `Error starting cracking session: ${response.message || 'Unknown error'}`;
                        console.error("Crack handshake error response:", response);
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: <pre>${JSON.stringify(response, null, 2)}</pre>`);
                    break;
                case 'generate_report':
                    appendToTerminal("Generating reports...");
                    response = await generateReports();
                    if (response.status === 'success' || response.status === 'no_events_or_failure') { // Backend returns 200 even if no events
                        userMessage = response.message || "Report generation process finished.";
                        if(response.json_report_path) {
                            userMessage += `<br>JSON report: ${response.json_report_path.replace(/</g, "&lt;").replace(/>/g, "&gt;")}`;
                        }
                        if(response.markdown_report_path) {
                            userMessage += `<br>Markdown report: ${response.markdown_report_path.replace(/</g, "&lt;").replace(/>/g, "&gt;")}`;
                        }
                    } else {
                        userMessage = `Error generating reports: ${response.message || 'Unknown error'}`;
                        console.error("Generate reports error response:", response);
                    }
                    appendToTerminal(userMessage);
                    if (!(response.status === 'success' || response.status === 'no_events_or_failure')) appendToTerminal(`Details: <pre>${JSON.stringify(response, null, 2)}</pre>`);
                    break;
                case 'clear':
                    while (terminalOutput.children.length > 1 && terminalOutput.firstChild !== terminalOutput.querySelector('.flex.items-center:has(input#terminalInput)')) {
                       terminalOutput.removeChild(terminalOutput.firstChild);
                    }
                    break;
                default:
                    userMessage = `-bash: ${command}: command not found<br>Type 'help' for available commands`;
                    appendToTerminal(userMessage);
            }
        } catch (error) {
            console.error("Command processing error:", error);
            appendToTerminal(`Error processing command: ${error.message}. Check console for details.`);
        }
      }
    });
  }

  const sidebarLinks = document.querySelectorAll('.sidebar-nav-link');
  sidebarLinks.forEach(link => {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      const command = this.dataset.command || this.dataset.action;
      if (command && terminalInput) {
        terminalInput.value = command;
        terminalInput.focus();
        appendToTerminal(`Executing from UI: ${command}`, false); // Display a less prominent message for UI clicks
        terminalInput.dispatchEvent(new KeyboardEvent('keypress', {'key': 'Enter', bubbles: true})); // Simulate Enter
      }
    });
  });

  const controlPanelCards = document.querySelectorAll('.hacker-card');
  controlPanelCards.forEach(card => {
    card.addEventListener('click', function(e) {
      const command = this.dataset.command || this.dataset.action;
      if (command && terminalInput) {
        terminalInput.value = command;
        terminalInput.focus();
        appendToTerminal(`Executing from UI: ${command}`, false);
        terminalInput.dispatchEvent(new KeyboardEvent('keypress', {'key': 'Enter', bubbles: true})); // Simulate Enter
      }
    });
  });

  const topNavInterfaceValue = document.getElementById('top-nav-interface-value');

  function updateTopNavInterface(interfaceName) {
    if (topNavInterfaceValue && interfaceName) {
      topNavInterfaceValue.textContent = interfaceName;
    } else if (topNavInterfaceValue) {
      topNavInterfaceValue.textContent = "N/A"; // Default if name is not provided
    }
  }

  async function fetchAndUpdateDefaultMonitorInterface() {
    try {
      const response = await fetch("/api/interfaces/default_monitor");
      if (response.ok) {
        const data = await response.json();
        if (data.status === "success" && data.interface) {
          updateTopNavInterface(data.interface);
        } else {
          updateTopNavInterface("Error"); // Or some other error indicator
          console.warn("Failed to get default monitor interface from API:", data.message);
        }
      } else {
        updateTopNavInterface("Error");
        console.error("Error fetching default monitor interface:", response.statusText);
      }
    } catch (error) {
      updateTopNavInterface("Error");
      console.error("Network error fetching default monitor interface:", error);
    }
  }

  async function generateReports() {
    // No body needed for this POST request as per current backend
    return await postData("/api/reporting/generate", {});
  }

  async function updateRootStatusDisplay() {
    try {
        const response = await fetch('/api/system/root_status'); // GET request
        const rootStatusDiv = document.getElementById('rootStatusDisplay');
        if (!rootStatusDiv) {
            console.error("rootStatusDisplay element not found in HTML.");
            return;
        }

        if (response.ok) {
            const data = await response.json();
            if (data.is_root) {
                rootStatusDiv.textContent = 'Active';
                rootStatusDiv.classList.remove('text-red-400');
                rootStatusDiv.classList.add('text-green-400');
            } else {
                rootStatusDiv.textContent = 'Inactive - Privileges Issue';
                rootStatusDiv.classList.remove('text-green-400');
                rootStatusDiv.classList.add('text-red-400');
                appendToTerminal("<span class='text-red-400'>WARNING: Server is not running with root privileges. Most features will fail.</span>");
            }
        } else {
            rootStatusDiv.textContent = 'Error';
            rootStatusDiv.classList.remove('text-green-400');
            rootStatusDiv.classList.add('text-red-400');
            appendToTerminal("<span class='text-red-400'>Error fetching root status from server.</span>");
            console.error("Error fetching root status:", response.statusText);
        }
    } catch (error) {
        const rootStatusDiv = document.getElementById('rootStatusDisplay');
        if (rootStatusDiv) {
            rootStatusDiv.textContent = 'Error';
            rootStatusDiv.classList.remove('text-green-400');
            rootStatusDiv.classList.add('text-red-400');
        }
        console.error('Network error fetching root status:', error);
        appendToTerminal("<span class='text-red-400'>Network error fetching root status from server.</span>");
    }
  }

  async function stopHandshakeCapture() {
    appendToTerminal("Attempting to stop handshake capture...");
    const response = await postData("/api/handshake/stop", {});
    const handshakeCtrlCard = document.querySelector('.hacker-card[data-action="handshake"]');
    const stopBtn = document.getElementById('stopHandshakeBtn');

    if (response.status === "success") {
        appendToTerminal(`Handshake capture stop initiated: ${response.message}`);
        if (handshakeCtrlCard) {
            handshakeCtrlCard.querySelector('.text-xs.bg-yellow-500\\/20').textContent = 'Stopped';
        }
        if(stopBtn) stopBtn.disabled = true;
    } else {
        appendToTerminal(`Error stopping handshake capture: ${response.message || 'Unknown error'}`);
        if (handshakeCtrlCard) {
            // Keep status as Running or Error if stop failed, or set to Unknown
            // For now, assume it might still be running if stop failed.
        }
    }
    // Optionally, update stats again if stopping might log a final count, though less likely
    // updateHandshakesCapturedStats();
  }

  const stopHandshakeBtn = document.getElementById('stopHandshakeBtn');
  if (stopHandshakeBtn) {
    stopHandshakeBtn.disabled = true; // Initially disabled
    stopHandshakeBtn.addEventListener('click', stopHandshakeCapture);
  }

  async function updateHandshakesCapturedStats() {
    try {
        const response = await fetch('/api/stats/handshakes_count');
        const countEl = document.getElementById('handshakesCapturedCount');
        const lastEl = document.getElementById('handshakesCapturedLast');

        if (!countEl || !lastEl) {
            console.error("Handshake stats elements not found in HTML.");
            return;
        }

        if (response.ok) {
            const data = await response.json();
            if (data.status === "success") {
                countEl.textContent = data.count !== undefined ? data.count : 'N/A';
                let lastTimeText = "Last: N/A";
                if (data.last_capture_timestamp) {
                    // Simple date formatting, can be improved with a library like moment.js or date-fns for "X minutes ago"
                    const d = new Date(data.last_capture_timestamp);
                    lastTimeText = `Last: ${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
                }
                lastEl.innerHTML = `<i class="fas fa-lock-open mr-1"></i> ${lastTimeText.replace(/</g, "&lt;").replace(/>/g, "&gt;")}`;
            } else {
                countEl.textContent = 'Error';
                lastEl.textContent = 'Last: Error';
            }
        } else {
            countEl.textContent = 'Error';
            lastEl.textContent = 'Last: Error';
            console.error("Error fetching handshake stats:", response.statusText);
        }
    } catch (error) {
        const countEl = document.getElementById('handshakesCapturedCount');
        const lastEl = document.getElementById('handshakesCapturedLast');
        if(countEl) countEl.textContent = 'Error';
        if(lastEl) lastEl.textContent = 'Last: Error';
        console.error('Network error fetching handshake stats:', error);
    }
  }

  fetchAndUpdateDefaultMonitorInterface(); // Fetch on initial load
  updateRootStatusDisplay(); // Fetch root status on load
  updateHandshakesCapturedStats(); // Fetch handshake stats on load

    if (terminalOutput && terminalInput) {
        const initialMessages = [
            "iNTRUDER v1.5 - Cyberpunk WiFi Pentesting Suite",
            "Initializing modules...",
            "[<span class='text-yellow-400'>!</span>] SocketIO connection available for real-time updates (stub handlers).",
            "----------------------------------------",
            "Type 'help' for available commands.",
            "----------------------------------------",
            "NOTE: UI elements for stats and control panel cards are currently STUBS and will not dynamically update based on commands yet."
        ];
        initialMessages.forEach(msg => appendToTerminal(msg));
    }
});

/*
Overall JS Recommendations:
- Implement full data parsing and UI updates for all Socket.IO events (e.g., 'handshake-update', 'network-stats').
- Ensure all API endpoints called (e.g., '/api/log-sniffer') are correct and match the backend implementation.
- Develop more robust UI update mechanisms. Instead of querySelector for general cards, use specific IDs or more targeted selectors
  for elements that need to change (e.g., status text, icons on control panel cards, values in stat cards).
- Implement actual "Stop" functionality for ongoing operations (Monitor, Scan, Handshake Capture, Deauth). This will require
  corresponding backend API endpoints to stop these processes.
- Error Handling: While postData has basic error handling, consider more user-friendly error messages in the terminal
  rather than just JSON stringified responses for all error cases.
- Input Sanitization: For commands displayed back in the terminal, ensure proper HTML escaping if user input could
  contain HTML characters (basic escaping added for command display).
- Code Structure: For more complex interactions, consider breaking down command handlers into smaller functions.
*/
