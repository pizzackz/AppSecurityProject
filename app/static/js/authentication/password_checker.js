document.addEventListener("DOMContentLoaded", () => {
    // Retrieve references to password input field, list items for each password complexity rule
    const passwordField = document.getElementById("password");
    const lengthCheck = document.getElementById("length-check");
    const uppercaseCheck = document.getElementById("uppercase-check");
    const lowercaseCheck = document.getElementById("lowercase-check");
    const numberCheck = document.getElementById("number-check");
    const symbolCheck = document.getElementById("symbol-check");

    /**
     * Update the validity status of a password complexity rule
     * @param {HTMLElement} element - The list item element for the rule
     * @param {boolean} condition - Whether the rule is satisfied
     */
    function updateCheck(element, condition) {
        const icon = element.querySelector('.icon');
        if (condition) {
            element.classList.remove("invalid");
            element.classList.add("valid");
            icon.classList.remove("bi-x-circle-fill");
            icon.classList.add("bi-check-circle-fill");
        } else {
            element.classList.remove("valid");
            element.classList.add("invalid");
            icon.classList.remove("bi-check-circle-fill");
            icon.classList.add("bi-x-circle-fill");
        }
    }

    /**
     * Check the complexity of the provided password and update the UI accordingly
     * @param {string} password - The password to check
     */
    function checkPasswordComplexity(password) {
        // Check for minimum length
        updateCheck(lengthCheck, password.length >= 8);
        // Check for at least one uppercase letter
        updateCheck(uppercaseCheck, /[A-Z]/.test(password));
        // Check for at least one lowercase letter
        updateCheck(lowercaseCheck, /[a-z]/.test(password));
        // Check for at elast 1 number
        updateCheck(numberCheck, /\d/.test(password));
        // Check for at least one symbol
        updateCheck(symbolCheck, /[!@#$%^&*(),.?":{}|<>]/.test(password));
    }

    // Add an event listener to the password field to check complexity on every input
    passwordField.addEventListener("input", function() {
        checkPasswordComplexity(passwordField.value);
    });
})