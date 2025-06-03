// Helper to display output messages
function showOutput(outputId, message, isError = false) {
    const outputElement = $(outputId);
    if (outputElement.length === 0) {
        console.warn("Output element not found:", outputId);
        // Attempt to create a temporary notification if main display fails
        if ($('#socket-status-output').length > 0) {
             $('#socket-status-output').text(`Output for ${outputId.substring(1)}: ${message.length > 50 ? message.substring(0,50)+'...' : message}`);
        }
        return;
    }
    var processedMessage = "";
    if (typeof message === 'object') {
        processedMessage = JSON.stringify(message, null, 2);
    } else {
        processedMessage = String(message); // Ensure it's a string
    }
    // Sanitize message before setting as HTML to prevent XSS. Display as text, converting newlines.
    outputElement.html($('<div/>').text(processedMessage).html().replace(/\n/g, '<br>').replace(/
/g, '<br>'));
    outputElement.css('color', isError ? '#ff6b6b' : '#00ff00'); // Cyberpunk red / bright green
    outputElement.scrollTop(outputElement[0].scrollHeight);
}

// Function to send AJAX requests
function sendApiRequest(url, method, data, outputId) {
    showOutput(outputId, "Sending request to " + url + "...", false);
    $.ajax({
        url: url,
        type: method,
        contentType: 'application/json',
        data: data ? JSON.stringify(data) : null,
        success: function(response) {
            showOutput(outputId, response);
        },
        error: function(xhr, status, error) {
            let errorMessage = `Error: ${xhr.status} ${error}`;
            if (xhr.responseJSON && xhr.responseJSON.message) {
                errorMessage = xhr.responseJSON.message;
            } else if (xhr.responseText) {
                try {
                    const parsedError = JSON.parse(xhr.responseText);
                    errorMessage = parsedError.message || JSON.stringify(parsedError);
                } catch (e) {
                    errorMessage = xhr.responseText;
                }
            }
            showOutput(outputId, errorMessage, true);
        }
    });
}

// ===== iNTRUDER v1.5 – Dashboard Terminal Emulation & Navigation =====
// Original template logic adapted from cyberpunk_interface3.js :contentReference[oaicite:9]{index=9}

// Boot Commands Display for iNTRUDER
const commands = String.raw`root「」~・iNTRUDER --> cd iNTRUDER_Project
root「」~・iNTRUDER_Project --> ls`;
const header = String.raw`
                                              

        ________  ___  ____  _____   ____  ____  ____  _____   ___
       /  ___  \/ _ \|  _ \| ____| |  _ \|  _ \|  _ \| ____| / _ \
      | |   | | | | | |_) |  _|   | | | | |_) | |_) |  _|  | | | |
      | |   | | | | |  _ <| |___  | |_| |  _ <|  _ <| |___ | |_| |
      |_|   |_| \___/|_| \_\_____| |____/|_| \_\_| \_\_____| \___/

`;

// Final ASCII Title for iNTRUDER
const finalTitle = String.raw`
██╗███╗   ██╗██████╗ ██████╗ ██████╗ ███████╗██████╗ ███████╗███████╗
██║████╗  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
██║██╔██╗ ██║██████╔╝██████╔╝██║  ██║█████╗  ██████╔╝█████╗  ███████╗
██║██║╚██╗██║██╔═══╝ ██╔═══╝ ██║  ██║██╔══╝  ██╔══██╗██╔══╝  ╚════██║
██║██║ ╚████║██║     ██║     ██████╔╝███████╗██║  ██║███████╗███████║
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝     ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
`;

// Typing & Rendering Helpers (unchanged logic)
let blink = document.querySelector('.blink');
const code = document.querySelector('.code');

const RandomNumber = (min, max) => {
  return Math.floor(Math.random() * (max - min + 1)) + min;
};

const Delay = (time) => {
  return new Promise((resolve) => setTimeout(resolve, time));
};

const ResetTerminal = () => {
  code.innerHTML = '<span class="blink">█</span>';
  blink = document.querySelector('.blink');
};

const RenderString = (characters) => {
  blink.insertAdjacentHTML('beforeBegin', characters);
};

const TypeString = async (characters) => {
  for (const character of characters.split('')) {
    await Delay(RandomNumber(50, 150));
    RenderString(character);
  }
};

const DrawLines = async (lines, min = 50, max = 500) => {
  for (const line of lines.split('\n')) {
    await Delay(RandomNumber(min, max));
    RenderString(`${line}\n`);
  }
};

const DrawCommands = async (commandsText) => {
  for (const line of commandsText.split('\n')) {
    const [currentDir, command] = line.split(' --> ');
    RenderString('\n');
    RenderString(`${currentDir} ➤ `);
    await TypeString(command);
    RenderString('\n');
  }
};

// Execute Terminal Sequence on Page Load
(async () => {
  await DrawCommands(" --> BOOTING iNTRUDER UI...");
  await Delay(100);
  RenderString("\n");
  await DrawCommands(commands);
  RenderString('\n');
  await DrawCommands('root「」~・iNTRUDER_Project --> node server.js');
  await DrawLines(header);
  await TypeString("\n\nWelcome to iNTRUDER v1.5.");
  await Delay(2000);
  ResetTerminal();
  await DrawCommands('root「」~・iNTRUDER_Project --> node dashboard.js');
  await DrawLines(finalTitle);
})();

// jQuery DOM Ready for Navigation & Theme Logic
$(document).ready(function () {
  // Remove initial glitch animation after load
  setTimeout(function () {
    $('.slider__inner').removeClass("glitch--animate");
  }, 2000);

  // Navigation Buttons
  $('#inicio').on('click', function () {
    $('#two, #three, #four, #five').hide();
    $('#one').show();
    $('.inicio').addClass("glitch--animate");
    setTimeout(() => { $('.inicio').removeClass("glitch--animate"); }, 1000);
  });

  $('#servicos').on('click', function () {
    $('#one, #two, #four, #five').hide();
    $('#three').show();
    $('.divserviços').addClass("glitch--animate");
    setTimeout(() => { $('.divserviços').removeClass("glitch--animate"); }, 1000);
  });

  $('#contato').on('click', function () {
    $('#one, #two, #three, #five').hide();
    $('#four').show();
    $('.contact').addClass("glitch--animate");
    setTimeout(() => { $('.contact').removeClass("glitch--animate"); }, 800);
  });

  // Reports & Utilities Button ### Hosted on Slide #5
  $(document).on('click', '#reportsBtn', function () {
    $('#one, #two, #three, #four').hide();
    $('#five').show();
    $('.divreports').addClass("glitch--animate");
    setTimeout(() => { $('.divreports').removeClass("glitch--animate"); }, 1000);
  });

  // Toggle Navbar Buttons
  $('#close').on('click', function () {
    if ($('#buttons').hasClass("inactive")) {
      $('#buttons').removeClass('inactive').addClass('active').show("blind");
      $('#navbar').animate({ height: '330px' });
    } else {
      $('#buttons').removeClass('active').addClass('inactive').hide("blind");
      $('#navbar').animate({ height: '80px' });
      $('#close').animate({ 'margin-top': '-5px' });
    }
  });

  // Theme Switching Logic
  $('#redtheme').on('click', function () {
    $('.header-presentation').addClass('glitch--animate');
    setTimeout(() => { $('.header-presentation').removeClass("glitch--animate"); }, 800);
    $(':root').css('--gold88', 'rgba(255, 0, 0, 0.53)');
    $(':root').css('--gold', '#ff0000');
    $(':root').css('--goldDark', '#ed2525');
    $(':root').css('--hovercolor', '#00ffbf');
    $(':root').css('--hovercolorbg', 'rgba(0, 255, 170, 0.25)');
    $(':root').css('--inputfocus', 'rgba(255, 23, 23, 0.644)');
    $(':root').css('--termcolor', '#0f0000');
  });

  $('#bluetheme').on('click', function () {
    $('.header-presentation').addClass('glitch--animate');
    setTimeout(() => { $('.header-presentation').removeClass("glitch--animate"); }, 800);
    $(':root').css('--gold88', 'rgba(0, 255, 213, 0.53)');
    $(':root').css('--gold', '#00ffd5');
    $(':root').css('--goldDark', '#25edc2');
    $(':root').css('--hovercolor', '#ffee00');
    $(':root').css('--hovercolorbg', 'rgba(255, 217, 0, 0.25)');
    $(':root').css('--inputfocus', 'rgba(23, 255, 216, 0.644)');
    $(':root').css('--termcolor', '#000f0d');
  });

  $('#goldtheme').on('click', function () {
    $('.header-presentation').addClass('glitch--animate');
    setTimeout(() => { $('.header-presentation').removeClass("glitch--animate"); }, 800);
    $(':root').css('--gold88', 'rgba(255, 215, 0, 0.53)');
    $(':root').css('--gold', '#ffd700');
    $(':root').css('--goldDark', '#eda725');
    $(':root').css('--hovercolor', '#ff0000');
    $(':root').css('--hovercolorbg', 'rgba(255, 0, 0, 0.25)');
    $(':root').css('--inputfocus', 'rgba(255, 220, 23, 0.644)');
    $(':root').css('--termcolor', '#0f0900');
  });

    // --- Start of Combined API/Socket.IO Code ---

    // Initialize Socket.IO
    try {
        const socket = io({ path: '/socket.io' }); // Explicit path, often helpful
        console.log('Attempting to connect Socket.IO...');
        showOutput('#socket-status-output', 'Socket.IO Connecting...', false);

        socket.on('connect', function() {
            console.log('Socket.IO connected successfully.');
            showOutput('#socket-status-output', 'Socket.IO Connected', false);
        });
        socket.on('disconnect', function(reason) {
            console.log('Socket.IO disconnected:', reason);
            showOutput('#socket-status-output', 'Socket.IO Disconnected: ' + reason, true);
        });
        socket.on('connect_error', (error) => {
            console.error('Socket.IO connection error:', error);
            showOutput('#socket-status-output', 'Socket.IO Connection Error: ' + error.message, true);
        });

        // Example listener for backend logs (to be expanded in later steps)
        socket.on('log_update', function(data) {
            console.log('Received log_update:', data);
            // This needs a dedicated log display area in the HTML, e.g., '#main_log_box'
            // For now, can use an existing output or console.
            // showOutput('#log-sniffer-output', data.log || JSON.stringify(data), false);
        });

    } catch (e) {
        console.error("Socket.IO client failed to initialize:", e);
        showOutput('#socket-status-output', 'Socket.IO client init error.', true);
    }

    // API Call Event Listeners
    $('#start-mon-btn').on('click', function() {
        const iface = $('#monitor-iface').val() || ""; // Default to empty string if not filed
        sendApiRequest('/api/monitor/start', 'POST', { iface: iface }, '#start-mon-output');
    });

    $('#log-sniffer-btn').on('click', function() {
        const iface = $('#scan-iface').val() || "";
        const duration = $('#scan-duration').val() || "30"; // Default duration
        sendApiRequest('/api/scan/start', 'POST', { interface: iface, duration: duration }, '#log-sniffer-output');
    });

    $('#scan-handshake-btn').on('click', function() {
        const data = {
            iface: $('#capture-iface').val() || "",
            ssid: $('#capture-ssid').val() || "",
            bssid: $('#capture-bssid').val() || "",
            channel: $('#capture-channel').val() || ""
        };
        sendApiRequest('/api/handshake/start', 'POST', data, '#scan-handshake-output');
    });

    $('#deauth-btn').on('click', function() {
        const data = {
            target_bssid: $('#deauth-bssid').val() || "",
            client_mac: $('#deauth-client').val() || "", // Default is broadcast handled by backend if empty
            iface: $('#deauth-iface').val() || "",
            count: $('#deauth-count').val() || "10" // Default count
        };
        if (!data.target_bssid) {
            showOutput('#deauth-output', 'Target BSSID is required for deauth attack.', true);
            return;
        }
        sendApiRequest('/api/deauth/start', 'POST', data, '#deauth-output');
    });

    $('#crack-btn').on('click', function() {
        const data = {
            handshake_file: $('#crack-handshake').val() || "",
            wordlist: $('#crack-wordlist').val() || ""
        };
        if (!data.handshake_file || !data.wordlist) {
            showOutput('#crack-output', 'Handshake file and Wordlist are required for cracking.', true);
            return;
        }
        sendApiRequest('/api/crack/start', 'POST', data, '#crack-output');
    });


    // --- Rogue AP Listeners ---
    $('#start-rogue-ap-btn').on('click', function() {
        const data = {
            iface: $('#rogue-ap-iface').val(),
            ssid: $('#rogue-ap-ssid').val(),
            channel: $('#rogue-ap-channel').val()
        };
        if (!data.iface || !data.ssid) {
            showOutput('#rogue-ap-output', 'Interface and SSID are required for Rogue AP.', true);
            return;
        }
        sendApiRequest('/api/rogue_ap/start', 'POST', data, '#rogue-ap-output');
    });

    $('#stop-rogue-ap-btn').on('click', function() {
        sendApiRequest('/api/rogue_ap/stop', 'POST', {}, '#rogue-ap-output');
    });

    // --- MITM Proxy Listeners ---
    $('#start-mitm-btn').on('click', function() {
        const data = {
            port: $('#mitm-port').val() || "8081",
            mode: $('#mitm-mode').val() || "transparent"
        };
        sendApiRequest('/api/mitm/start', 'POST', data, '#mitm-output');
    });

    $('#stop-mitm-btn').on('click', function() {
        sendApiRequest('/api/mitm/stop', 'POST', {}, '#mitm-output');
    });

    // --- WPS Attack Listener ---
    $('#start-wps-btn').on('click', function() {
        const data = {
            iface: $('#wps-iface').val(),
            bssid: $('#wps-bssid').val(),
            timeout: $('#wps-timeout').val() || "3600",
            multi: $('#wps-multi').val() === "true"
        };
        if (!data.iface || !data.bssid) {
            showOutput('#wps-output', 'Interface and Target BSSID are required for WPS Attack.', true);
            return;
        }
        sendApiRequest('/api/wps/start', 'POST', data, '#wps-output');
    });

    // --- Additional Listeners End ---

    // --- End of Combined API/Socket.IO Code ---
});
