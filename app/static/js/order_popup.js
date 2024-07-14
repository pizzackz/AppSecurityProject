document.addEventListener("DOMContentLoaded", function () {
    // Get all the buttons that open the modals
    var modalButtons = document.querySelectorAll(".openModalBtn");

    // Get all the close buttons
    var closeButtons = document.querySelectorAll(".close");

    // Add event listener to each button
    modalButtons.forEach(function(button) {
        button.addEventListener("click", function() {
            var modalId = this.getAttribute("data-modal");
            var modal = document.getElementById(modalId);
            modal.style.display = "block";
            document.body.style.overflow = "hidden";
        });
    });

    // Add event listener to each close button
    closeButtons.forEach(function(button) {
        button.addEventListener("click", function() {
            var modalId = this.getAttribute("data-modal");
            var modal = document.getElementById(modalId);
            modal.style.display = "none";
            document.body.style.overflow = "auto";
        });
    });

    // Add event listener to window to close modal when clicking outside of it
    window.addEventListener("click", function(event) {
        if (event.target.classList.contains("modal")) {
            event.target.style.display = "none";
            document.body.style.overflow = "auto";
        }
    });
});
