// Check if all mandatory fields are filled
function checkMandatoryFields(fields) {
    for (let field of fields) {
        if (!field.value.trim() && field.hasAttribute("required")) {
            return false;
        }
    }
    return true;
}


// Check if any optional fields are filled
function checkAnyOptionalFields(fields) {
    for (let field of fields) {
        if (field.value.trim() && !field.hasAttribute("required")) {
            return true;
        }
    }
    return false;
}


// Enable or disable submit buttons based on field checks
function toggleSubmitButtons(buttons, condition) {
    buttons.forEach((button) => {
        if (condition) {
            button.classList.remove("disabled");
            button.disabled = false;
        } else {
            button.classList.add("disabled");
            button.disabled = true;
        }
    });
}


// Main function to check fields and update submit buttons
function checkFields(formId) {
    const form = document.getElementById(formId);
    if (!form) {
        return;
    }

    const fields = form.querySelectorAll("input:not(#csrf_token), textarea");  // Get all fields initially
    const mandatorySubmitButtons = form.querySelectorAll("button:not(.optional-submit).submit-disabler");  // Get all mandatory submit buttons
    const optionalSubmitButtons = form.querySelectorAll("button.optional-submit.submit-disabler");  // Get all optional submit buttons
    
    const allMandatoryFieldsFilled = checkMandatoryFields(fields);
    const anyOptionalFieldFilled = checkAnyOptionalFields(fields);

    toggleSubmitButtons(mandatorySubmitButtons, allMandatoryFieldsFilled);
    toggleSubmitButtons(optionalSubmitButtons, anyOptionalFieldFilled);
}


// Ensure it works for all forms, even future ones
document.addEventListener("DOMContentLoaded", () => {
    const forms = document.querySelectorAll("form");
    forms.forEach((form) => {
        form.addEventListener("input", () => checkFields(form.id)); // Check whenever any field changes
        checkFields(form.id); // Initial check
    });
});
