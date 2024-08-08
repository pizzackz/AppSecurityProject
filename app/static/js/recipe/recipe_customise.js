generate_button = document.getElementById('generate_button');
generate_button.addEventListener('click', sendMessage);
const csrfToken = document.getElementById('_csrf_token').value;
reset_button = document.getElementById('reset_button');
reset_button.addEventListener('click', reset_output);
var original_value = document.getElementById('output').innerHTML;

async function sendMessage() {
    const user_request = document.getElementById('request').value;
    const response = await fetch('/api/recipe-customise-ai', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({request: user_request})
    })
    const data = await response.json();
    document.getElementById('output').innerText = data.content;
}

function reset_output() {
    document.getElementById('output').innerHTML = original_value;
}
