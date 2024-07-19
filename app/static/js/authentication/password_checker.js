document.addEventListener("DOMContentLoaded", () => {
    const passwordField = document.getElementById("password") || document.getElementById("new_password");
    const confirmPasswordField = document.getElementById("confirm_password");
    const signupButton = document.querySelector("button[type='submit']");

    const lengthCheck = document.getElementById("length-check");
    const uppercaseCheck = document.getElementById("uppercase-check");
    const lowercaseCheck = document.getElementById("lowercase-check");
    const numberCheck = document.getElementById("number-check");
    const symbolCheck = document.getElementById("symbol-check");

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

    function checkPasswordComplexity(password) {
        updateCheck(lengthCheck, password.length >= 8);
        updateCheck(uppercaseCheck, /[A-Z]/.test(password));
        updateCheck(lowercaseCheck, /[a-z]/.test(password));
        updateCheck(numberCheck, /\d/.test(password));
        updateCheck(symbolCheck, /[!@#$%^&*(),.?":{}|<>]/.test(password));
    }

    function allChecksPassed() {
        return document.querySelectorAll('.password-checker .valid').length === 5;
    }

    function validateForm() {
        const passwordsMatch = passwordField.value === confirmPasswordField.value;
        const passwordValid = allChecksPassed();
        signupButton.disabled = !(passwordValid && passwordsMatch);
    }

    passwordField.addEventListener("input", function() {
        checkPasswordComplexity(passwordField.value);
        validateForm();
    });

    confirmPasswordField.addEventListener("input", validateForm);
});
