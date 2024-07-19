generate_button = document.getElementById('generate_button');
generate_button.addEventListener('click', sendMessage);

const csrfToken = document.getElementById('_csrf_token').value;

// Send Json in dictionary, send json to server
async function sendMessage() {
//  if (!token) {
//      document.getElementById('response').innerText = 'Please log in first.';
//      return;
//  }
    const cuisine = document.getElementById('cuisine').value;
    const ingredients = document.getElementById('ingredients').value;
    const dietary_preference = document.getElementById('dietary_preference').value;
    const allergy = document.getElementById('allergy').value;
    const meal_type = document.getElementById('meal_type').value;
    const cooking_time = document.getElementById('cooking_time').value;
    const difficulty = document.getElementById('difficulty').value;
    const remarks = document.getElementById('remarks').value;

    const response = await fetch('/api/recipe-creator-ai', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({cuisine: cuisine}, { ingredients: ingredients },
        { dietary_preference: dietary_preference }, { allergy: allergy }, { meal_type: meal_type },
        { cooking_time: cooking_time }, { difficulty: difficulty }, { remarks: remarks })

    })
    const data = await response.json();
    document.getElementById('output').innerText = data.content;
}





//const response = await fetch('/api/recipe-creator-ai', {
//    method: 'POST',
//    headers: {
//        'Content-Type': 'application/json',
//        'Authorisation': 'Bearer ${token}'
//    },
//    body: JSON.stringify({cuisine: cuisine}, { message: message }, { ingredients: ingredients },
//    { dietary_preference: dietary_preference }, { allergy: allergy }, { meal_type: meal_type },
//    { cooking_time: cooking_time }, { difficulty: difficulty }, { remarks: remarks })
//
//})
//const data = await response.json();
//document.getElementById('output').innerText = data.message;

//    cuisine = SelectMultipleField('Cuisine', validators=[DataRequired()] ,choices=[("any", "Any"), ("chinese", "Chinese"), ("indian", "Indian"), ("japanese", "Japanese"), ("korean", "Korean"), ("thai", "Thai"), ("western", "Western"), ("french", "French"), ("mediterranean", "Mediterranean") ,("others", "Others")], render_kw={"class": "form-control m-2"})
//    # cuisine = BooleanField('Cuisine')
//    ingredients = StringField('Ingredients', render_kw={"class": "form-control m-2"})
//    # dietary_preference = BooleanField('Dietary Preference', choices=[("nil", "Nil"), ("vegetarian", "Vegetarian"), ("vegan", "Vegan"), ("gluten_free", "Gluten Free"), ("dairy_free", "Dairy Free"), ("nut_free", "Nut Free"), ("others", "Others")], render_kw={"class": "form-control m-2"})
//
//    # allergy = BooleanField('Allergy', choices=[("nil", "Nil"), ("peanut", "Peanut"), ("tree_nut", "Tree Nut"), ("shellfish", "Shellfish"), ("fish", "Fish"), ("soy", "Soy"), ("wheat", "Wheat"), ("dairy", "Dairy"), ("egg", "Egg"), ("others", "Others")], render_kw={"class": "form-control m-2"})
//
//    # meal_type = BooleanField('Meal Type', choices=[("nil", "Nil"), ("breakfast", "Breakfast"), ("lunch", "Lunch"), ("dinner", "Dinner"), ("snack", "Snack"), ("dessert", "Dessert"), ("others", "Others")], render_kw={"class": "form-control m-2"})
//
//    cooking_time = IntegerRangeField('Cooking Time (minutes)', [validators.NumberRange(min=1, max=180)], render_kw={"class": "form-control m-2"})
//    difficulty = SelectField('Difficulty', choices=[("easy", "Easy"), ("medium", "Medium"), ("hard", "Hard")], render_kw={"class": "form-control m-2"})
//    remarks = TextAreaField('Remarks', render_kw={"class": "form-control m-2"})





//clear local storage
function clear_storage() {
    localStorage.clear();
}



