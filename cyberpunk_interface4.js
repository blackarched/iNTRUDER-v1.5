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
});

