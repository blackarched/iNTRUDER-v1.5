import re

def insert_into_div(html_content, div_class, new_elements_html):
    # This pattern looks for the div and its immediate content (e.g., h2, slidetitle).
    # It aims to insert the new_elements_html before an existing <ul> or at the end of the known static content if no <ul>.
    # It also captures any content between the slidetitle and the ul (g2_content_after_slidetitle)
    pattern = re.compile(
        r'(<div class="' + div_class + r'">\s*<h2.*?<\/h2>\s*<div class="slidetitle">.*?<\/div>)' +
        r'(.*?)' +  # Non-greedy match for any content before an optional UL
        r'(<ul.*?>.*?<\/ul>)?' +
        r'(\s*<\/div>)',
        re.DOTALL
    )

    def replacer(match):
        g1_opening_static_content = match.group(1)
        g2_content_after_slidetitle_and_before_ul = match.group(2) # Content between slidetitle and UL (or end of div)
        g3_existing_ul = match.group(3) # The UL itself, if present
        g4_closing_div = match.group(4)

        # Ensure new_elements_html is placed after g2, then followed by g3 (if it exists)
        # If g2 contains primarily whitespace or is empty, it's fine. If it contains other structural elements,
        # they will be preserved before the new_elements_html.

        # Add margin-top to the new feature controls for spacing
        new_elements_with_style = new_elements_html.replace(
            '<div class="feature-controls"',
            '<div class="feature-controls" style="margin-top: 10px;"',
            1
        )

        if g3_existing_ul:
            # Ensure the existing ul also has a margin-top if it directly follows the new elements.
            styled_ul = g3_existing_ul.replace('<ul>', '<ul style="margin-top: 10px;">', 1)
            # Insert new elements, then the (potentially styled) existing ul
            return g1_opening_static_content + g2_content_after_slidetitle_and_before_ul + new_elements_with_style + styled_ul + g4_closing_div
        else:
            # Insert new elements, no existing ul to worry about
            return g1_opening_static_content + g2_content_after_slidetitle_and_before_ul + new_elements_with_style + g4_closing_div

    modified_content, num_replacements = pattern.subn(replacer, html_content)
    if num_replacements == 0:
        print(f"Warning: Div with class '{div_class}' not found or pattern did not match. No changes made for this section.")
    return modified_content

with open("index.html", "r") as f:
    original_html_content = f.read()

current_html_processing = original_html_content

# --- Monitor Mode Elements ---
monitor_mode_html = '''
                      <!-- Monitor Mode Controls START -->
                      <div class="feature-controls" augmented-ui="tl-clip br-clip exe" style="padding:10px;">
                        <div class="inputgroup" style="margin-bottom: 5px;">
                          <span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Interface:</span>
                          <input type="text" id="monitor-iface" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="e.g., wlan0" style="width: 120px; font-size: 0.9em;">
                        </div>
                        <button id="start-mon-btn" class="button" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" style="margin-top:5px; font-size: 0.9em; padding: 5px 10px;">Start Monitor</button>
                        <div id="start-mon-output" class="output-display" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" style="height: 50px; overflow-y: auto; margin-top: 10px; padding: 5px; font-size: 0.8em; background-color: rgba(0,0,0,0.2);">Monitor mode output...</div>
                      </div>
                      <!-- Monitor Mode Controls END -->
'''
current_html_processing = insert_into_div(current_html_processing, "servone", monitor_mode_html)

# --- Handshake Capture Elements ---
handshake_capture_html = '''
                      <!-- Handshake Capture Controls START -->
                      <div class="feature-controls" augmented-ui="tl-clip br-clip exe" style="padding:10px;">
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Mon Interface:</span><input type="text" id="capture-iface" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="e.g., wlan0mon" style="width: 120px; font-size: 0.9em;"></div>
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Target SSID:</span><input type="text" id="capture-ssid" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="Target SSID" style="width: 120px; font-size: 0.9em;"></div>
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Target BSSID:</span><input type="text" id="capture-bssid" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="Target BSSID" style="width: 120px; font-size: 0.9em;"></div>
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Channel (opt):</span><input type="text" id="capture-channel" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="Optional" style="width: 120px; font-size: 0.9em;"></div>
                        <button id="scan-handshake-btn" class="button" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" style="margin-top:5px; font-size: 0.9em; padding: 5px 10px;">Capture Handshake</button>
                        <div id="scan-handshake-output" class="output-display" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" style="height: 60px; overflow-y: auto; margin-top: 10px; padding: 5px; font-size: 0.8em; background-color: rgba(0,0,0,0.2);">Handshake capture output...</div>
                      </div>
                      <!-- Handshake Capture Controls END -->
'''
current_html_processing = insert_into_div(current_html_processing, "servthree", handshake_capture_html)

# --- Deauth Attack Elements ---
deauth_attack_html = '''
                      <!-- Deauth Attack Controls START -->
                      <div class="feature-controls" augmented-ui="tl-clip br-clip exe" style="padding:10px;">
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Mon Interface:</span><input type="text" id="deauth-iface" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="e.g., wlan0mon" style="width: 120px; font-size: 0.9em;"></div>
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Target BSSID:</span><input type="text" id="deauth-bssid" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="Target BSSID (Req)" style="width: 120px; font-size: 0.9em;"></div>
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Client MAC (opt):</span><input type="text" id="deauth-client" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="Default: Broadcast" style="width: 120px; font-size: 0.9em;"></div>
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Packet Count:</span><input type="text" id="deauth-count" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="e.g., 10" style="width: 120px; font-size: 0.9em;"></div>
                        <button id="deauth-btn" class="button" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" style="margin-top:5px; font-size: 0.9em; padding: 5px 10px;">Execute Deauth</button>
                        <div id="deauth-output" class="output-display" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" style="height: 60px; overflow-y: auto; margin-top: 10px; padding: 5px; font-size: 0.8em; background-color: rgba(0,0,0,0.2);">Deauth attack output...</div>
                      </div>
                      <!-- Deauth Attack Controls END -->
'''
current_html_processing = insert_into_div(current_html_processing, "servfour", deauth_attack_html)

# --- WPA Cracking Elements ---
wpa_cracking_html = '''
                      <!-- WPA Cracking Controls START -->
                      <div class="feature-controls" augmented-ui="tl-clip br-clip exe" style="padding:10px;">
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">.cap File Path:</span><input type="text" id="crack-handshake" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="Path to .cap file" style="width: 120px; font-size: 0.9em;"></div>
                        <div class="inputgroup" style="margin-bottom: 5px;"><span class="input-label" augmented-ui="tl-clip br-clip exe" style="margin-right:5px; font-size: 0.9em;">Wordlist Path:</span><input type="text" id="crack-wordlist" class="inputfield" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" placeholder="Path to wordlist" style="width: 120px; font-size: 0.9em;"></div>
                        <button id="crack-btn" class="button" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" style="margin-top:5px; font-size: 0.9em; padding: 5px 10px;">Crack Handshake</button>
                        <div id="crack-output" class="output-display" augmented-ui="tr-clip tl-clip bl-clip br-clip exe" style="height: 60px; overflow-y: auto; margin-top: 10px; padding: 5px; font-size: 0.8em; background-color: rgba(0,0,0,0.2);">WPA cracking output...</div>
                      </div>
                      <!-- WPA Cracking Controls END -->
'''
current_html_processing = insert_into_div(current_html_processing, "servfive", wpa_cracking_html)

if current_html_processing == original_html_content:
    print("No changes were made to index.html by the Python script. Check patterns in modify_html.py and the structure of index.html.")
else:
    with open("index.html", "w") as f:
        f.write(current_html_processing)
    print("index.html successfully modified by Python script.")
