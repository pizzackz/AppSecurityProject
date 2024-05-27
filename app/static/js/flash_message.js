
// Old Things
if (document.querySelector(".popup:not(.alert-dismissible)")) {
  const popup = document.querySelector(".popup:not(.alert-dismissible)");
  const closeButton = document.querySelector(".popup button");

  closeButton.addEventListener("click", () => {
    popup.classList.add("close");
  });

  setTimeout(() => {
    if (popup) {
      popup.classList.add("close");
    }
  }, 10000);
}



function display_popup(message, status) {
    var popup = document.getElementById('popup');
    if (status == 'info') {
      popup.innerHTML = `
      <span class="bi bi-info-circle" id="exclamation"></span>
      <span class="msg">` + message + `</span>
      <div id="close-btn">
        <span class="bi bi-x"></span>
      </div>
    `;
       popup.style.backgroundColor = "rgb(48, 75, 134)";
       console.log('Info')
    }
    else if (status == 'error') {
      popup.innerHTML = `
      <span class="bi bi-exclamation-circle" id="exclamation"></span>
      <span class="msg">Error: ` + message + `</span>
      <div id="close-btn">
        <span class="bi bi-x"></span>
      </div>
    `;
       popup.style.backgroundColor = "rgb(135,41,41)";

    }
    else if (status == 'warning') {
      popup.innerHTML = `
      <span class="bi bi-exclamation-circle" id="exclamation"></span>
      <span class="msg">Error: ` + message + `</span>
      <div id="close-btn">
        <span class="bi bi-x"></span>
      </div>
    `;
       popup.style.backgroundColor = "rgb(255, 255, 0)";

    }
    else if (status == 'success') {
      popup.innerHTML = `
      <span class="bi bi-check-lg" id="exclamation"></span>
      <span class="msg">` + message + `</span>
      <div id="close-btn">
        <span class="bi bi-x"></span>
      </div>
    `;
       popup.style.backgroundColor = "rgb(61, 92, 52)";
       console.log('Success')
    }
    popup.classList.remove('hide');
    popup.classList.add('show1');

    var close_btn = document.getElementById('close-btn');
    setTimeout(hide_popup, 9000);
    close_btn.addEventListener('click', hide_popup);
}

function hide_popup() {
    var popup = document.getElementById('popup');
    popup.classList.remove('show1');
    popup.classList.add('hide');
}