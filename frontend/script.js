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

    socket.on('handshake-update', (data) => { // Example: For real-time handshake chart updates
        if (!handshakeChart || !data) return;
        // Process data and update handshakeChart similarly
        // e.g., data might contain { timestamp: 'HH:MM', handshakes: 5, deauths: 100 }
        // This part needs actual data structure from backend to be implemented
        appendToTerminal(`[Socket.IO] Handshake data received: ${JSON.stringify(data)}`);
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
    return await postData("/api/log-sniffer", { bssid, channel, ssid });
  }

  async function startDeauthAttack(bssid, client_mac = "", count = "100", iface = "wlan0mon") {
    return await postData("/api/deauth", { bssid, client: client_mac, count, interface: iface });
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
                    if (response.status === 'success') {
                        userMessage = `Monitor mode successfully started on ${response.data && response.data.interface ? response.data.interface : (args[0] || 'default interface')}.`;
                        document.getElementById('top-nav-interface-value').textContent = response.data && response.data.interface ? response.data.interface : (args[0] || 'wlan0mon');
                        const monitorCard = document.querySelector('.hacker-card[data-action="monitor"]');
                        if (monitorCard) {
                            monitorCard.querySelector('.text-xs.bg-green-500\\/20').textContent = 'Active';
                            monitorCard.querySelector('.w-3.h-3.rounded-full').classList.add('bg-green-500', 'animate-pulse');
                            monitorCard.querySelector('.text-xs.text-gray-400').textContent = `Interface: ${response.data && response.data.interface ? response.data.interface : (args[0] || 'wlan0mon')}`;
                        }
                    } else {
                        userMessage = `Error starting monitor mode: ${response.message}`;
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: ${JSON.stringify(response, null, 2)}`);
                    break;
                case 'scan':
                    appendToTerminal("Starting network scan...");
                    response = await startNetworkScan(args[0]);
                    if (response.status === 'success' && response.data) {
                        userMessage = `Network scan completed. Found ${response.data.networks_found_count || 0} networks.`;
                        const networksFoundCard = document.querySelector('.glass-effect.rounded-xl.p-6:nth-child(1) h3');
                        if (networksFoundCard) networksFoundCard.textContent = response.data.networks_found_count || '0';

                        const scanCard = document.querySelector('.hacker-card[data-action="scan"]');
                        if (scanCard) {
                             scanCard.querySelector('.text-xs.bg-blue-500\\/20').textContent = 'Completed';
                             scanCard.querySelector('.text-xs.text-gray-400').textContent = `Last: Just now`;
                        }
                        // Note: networkAnalyticsChart is primarily updated by Socket.IO 'network-stats' event.
                        // If scan API provides a list of networks, it could be displayed in terminal or a table, not directly on the time-series chart here.
                        if(response.data.scan_results && Array.isArray(response.data.scan_results)) {
                            appendToTerminal(`Networks: <pre>${JSON.stringify(response.data.scan_results.slice(0,5), null, 2)}</pre>... (showing first 5)`);
                        }
                    } else {
                        userMessage = `Error during network scan: ${response.message}`;
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: ${JSON.stringify(response, null, 2)}`);
                    break;
                case 'handshake':
                    if (args.length < 1) {
                        appendToTerminal("Usage: handshake &lt;bssid&gt; [channel] [ssid]");
                        break;
                    }
                    appendToTerminal(`Starting handshake capture for BSSID ${args[0]}...`);
                    response = await startHandshakeCapture(args[0], args[1], args[2]);
                    if (response.status === 'success' && response.data) {
                        userMessage = `Handshake capture started for ${response.data.ssid || args[0]}. Status: ${response.message || 'Ongoing'}`;
                        const handshakesCapturedCard = document.querySelector('.glass-effect.rounded-xl.p-6:nth-child(2) h3');
                        if (handshakesCapturedCard && response.data.handshakes_captured_count) handshakesCapturedCard.textContent = response.data.handshakes_captured_count;

                        const handshakeCtrlCard = document.querySelector('.hacker-card[data-action="handshake"]');
                        if (handshakeCtrlCard) {
                            handshakeCtrlCard.querySelector('.text-xs.bg-yellow-500\\/20').textContent = 'Active';
                            handshakeCtrlCard.querySelector('.text-xs.text-gray-400').textContent = `SSID: ${response.data.ssid || args[2] || args[0]}`;
                        }
                        // handshakeChart should be updated by a dedicated socket.io event or if API provides full chart data
                    } else {
                        userMessage = `Error starting handshake capture: ${response.message}`;
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: ${JSON.stringify(response, null, 2)}`);
                    break;
                case 'deauth':
                    if (args.length < 1) {
                        appendToTerminal("Usage: deauth &lt;bssid&gt; [client_mac] [count] [interface]");
                        break;
                    }
                    appendToTerminal(`Starting deauth attack on BSSID ${args[0]}...`);
                    response = await startDeauthAttack(args[0], args[1], args[2], args[3]);
                    if (response.status === 'success' && response.data) {
                        userMessage = `Deauth attack on ${args[0]} finished. Packets sent: ${response.data.packets_sent || 'N/A'}.`;
                        const deauthAttacksCard = document.querySelector('.glass-effect.rounded-xl.p-6:nth-child(3) h3');
                        if (deauthAttacksCard && response.data.deauth_attacks_count) deauthAttacksCard.textContent = response.data.deauth_attacks_count;

                        const deauthCtrlCard = document.querySelector('.hacker-card[data-action="deauth"]');
                        if(deauthCtrlCard) {
                            deauthCtrlCard.querySelector('.text-xs.bg-red-500\\/20').textContent = 'Finished'; // Or 'Active' if it's ongoing
                        }
                        // handshakeChart should be updated by a dedicated socket.io event or if API provides full chart data
                    } else {
                        userMessage = `Error during deauth attack: ${response.message}`;
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: ${JSON.stringify(response, null, 2)}`);
                    break;
                case 'crack':
                    if (args.length < 2) {
                        appendToTerminal("Usage: crack &lt;cap_file&gt; &lt;wordlist_file&gt;");
                        break;
                    }
                    appendToTerminal(`Starting handshake cracking for ${args[0]}...`);
                    response = await startCrackHandshake(args[0], args[1]);
                     if (response.status === 'success' && response.data) {
                        userMessage = `Cracking session for ${args[0]} status: ${response.message}.`;
                        if(response.data.password_found) {
                             userMessage += ` Password found: <span class='text-green-400 font-bold'>${response.data.password}</span>`;
                        } else {
                             userMessage += " Password not found.";
                        }
                        const crackingSessionsCard = document.querySelector('.glass-effect.rounded-xl.p-6:nth-child(4) h3');
                        if(crackingSessionsCard && response.data.cracking_sessions_count) crackingSessionsCard.textContent = response.data.cracking_sessions_count;
                    } else {
                        userMessage = `Error starting cracking session: ${response.message}`;
                    }
                    appendToTerminal(userMessage);
                    if (response.status !== 'success') appendToTerminal(`Details: ${JSON.stringify(response, null, 2)}`);
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
  // This element is updated by the 'monitor' command.

    if (terminalOutput && terminalInput) {
        const initialMessages = [
            "iNTRUDER v1.5 - Cyberpunk WiFi Pentesting Suite",
            "Initializing modules...",
            "[<span class='text-yellow-400'>!</span>] SocketIO connection available for real-time updates.",
            "----------------------------------------",
            "Type 'help' for available commands.",
            "----------------------------------------"
        ];
        initialMessages.forEach(msg => appendToTerminal(msg));
    }
});
