generate_button = document.getElementById('generate_button');
generate_button.addEventListener('click', sendMessage);
const csrfToken = document.getElementById('_csrf_token').value;

async function sendMessage() {
    const cuisine = document.getElementById('cuisine').value;
    const ingredients = document.getElementById('ingredients').value;
    const dietary_preference = document.getElementById('dietary_preference').value;
    const allergy = document.getElementById('allergy').value;
    const meal_type = document.getElementById('meal_type').value;
    const difficulty = document.getElementById('difficulty').value;
    const remarks = document.getElementById('remarks').value;

    const response = await fetch('/api/recipe-creator-ai', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify( {cuisine: cuisine, ingredients: ingredients ,
         dietary_preference: dietary_preference , allergy: allergy , meal_type: meal_type ,
         difficulty: difficulty , remarks: remarks })

    })
    const data = await response.json();
    document.getElementById('output').innerText = data.content;
}




