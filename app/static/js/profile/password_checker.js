document.addEventListener("DOMContentLoaded", function() {
    const newPasswordInput = document.getElementById("new_password");
    const confirmPasswordInput = document.getElementById("confirm_password");
    const saveButton = document.querySelector("button[type='submit']");
    const mismatchMessage = document.getElementById("password-mismatch-message");

    // Password complexity indicators
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

    function passwordsMatch() {
        return newPasswordInput.value === confirmPasswordInput.value;
    }

    function validateForm() {
        const passwordValid = document.querySelectorAll('.password-checker .valid').length === 5;
        const passwordsAreMatching = passwordsMatch();

        if (passwordValid && passwordsAreMatching) {
            saveButton.classList.remove("disabled");
        } else {
            saveButton.classList.add("disabled");
        }

        if (mismatchMessage) {
            mismatchMessage.style.display = passwordsAreMatching ? 'none' : 'block';
        }
    }

    if (newPasswordInput && confirmPasswordInput) {
        newPasswordInput.addEventListener("input", function() {
            checkPasswordComplexity(newPasswordInput.value);
            validateForm();
        });

        confirmPasswordInput.addEventListener("input", validateForm);
    }
});
