var ingredient_list = [];

// Remove ingredient
function remove_ingredient(num) {
    ingredient_list.splice(num, 1);
    display_ingredient();
}

function display_ingredient() {
    var ingredient_itemHTML = ""
    for (i = 0; i < ingredient_list.length; i++) {
        ingredient_itemHTML += '<div class="ingredient_item" id="' + ingredient_list[i] +  `" style="width:fit-content">
        <i class="bi bi-x remove_ingredient" id="remove_` + ingredient_list[i] + '" onclick="remove_ingredient(' + i + `)"></i>
        <span class="item">` + ingredient_list[i] + "</span></div>";
    }
    document.getElementById('ingredient_items_list').innerHTML = ingredient_itemHTML;
    remove_all.classList.remove('disabled')
    if (ingredient_itemHTML == "") {
        const remove_all = document.getElementById('remove_all');
        const search = document.getElementById('search');
        remove_all.classList.add('disabled')
    }
}

document.addEventListener("DOMContentLoaded", function() {
    const form1 = document.getElementById('form1');
    const add_item = document.getElementById("add_ingredient");
    autocompletion();
    display_ingredient();
    add_item.addEventListener('click', function() { // Add event listener to adding ingredient button
        var ingredient = document.getElementById('ingredient').value;
        ingredient = ingredient.toLowerCase();
        if (ingredient.trim() == '') {
            display_popup('The input is empty.', 'error')
        }
        else {
            var regex = /^[a-zA-Z\s,]+$/;
            var arr = ingredient.split(',');
            console.log(arr)
            if (regex.test(ingredient)) {
                for (i=0;i<arr.length;i++) {
                    console.log(arr[i]);
                    if (ingredient_list.includes(arr[i])) {
                        display_popup(arr[i] + ' is already added.', 'error');
                    }
                    else {
                        if ((arr[i]).trim() == '') {
                            display_popup('The input is empty.', 'error');
                        }
                        else {
                            ingredient_list.push(arr[i]);
                            display_ingredient;
                        }
                    }
                }
            }
            else {
                display_popup('Letters, spaces and commas are only accepted.', 'error');
            }
        }
        display_ingredient();
    })
    const remove_all = document.getElementById('remove_all');
    remove_all.addEventListener('click', function() {
        ingredient_list = [];
        display_ingredient();
    })
    var ingredient_input = document.getElementById('ingredient');
    ingredient_input.addEventListener('input', autocompletion);
})

// Ingredient input autocomplete


function autocompletion() {
    var ingredient_input = document.getElementById('ingredient');
    var ingredient = ingredient_input.value;
    ingredient = ingredient.toLowerCase();
    console.log(ingredient);
    const add_item = document.getElementById("add_ingredient");
    add_item.classList.remove('disabled');
    if (ingredient == "") {
        add_item.classList.add('disabled');
    }
    var arr = ingredient.split(',');
    ingredient = arr[arr.length - 1];
    ingredient = ingredient.trim();
    // generate wordList of ingredients
    var wordList = [
        'apple', 'banana', 'chicken', 'carrot', 'tomato', 'potato', 'beef', 'pork', 'onion', 'garlic', 'pepper', 'cucumber', 'lettuce', 'spinach', 'mushroom', 'broccoli', 'peas', 'corn', 'rice', 'pasta', 'noodles', 'bread', 'flour', 'sugar', 'salt', 'pepper', 'cinnamon', 'paprika', 'cumin', 'curry', 'thyme', 'basil', 'oregano', 'parsley', 'sage', 'rosemary', 'cilantro', 'coriander', 'ginger', 'turmeric', 'saffron', 'cinnamon', 'nutmeg', 'vanilla', 'chocolate', 'cocoa', 'honey', 'maple', 'syrup', 'milk', 'cream', 'butter', 'cheese', 'yogurt', 'egg', 'mayo', 'ketchup', 'mustard', 'soy', 'sauce', 'vinegar', 'oil', 'water', 'juice', 'soda', 'beer', 'wine', 'whiskey', 'vodka', 'rum', 'tequila', 'gin', 'brandy', 'cognac', 'liqueur', 'vermouth', 'champagne', 'sparkling', 'wine', 'prosecco', 'sake', 'soju', 'baijiu', 'baiju', 'baijiu', 'baiju'];

    var matchingWords = [];

    for (var i = 0; i < wordList.length; i++) {

        var list_word = wordList[i];
        // Check if the first letter matches the first letter of the given word
        if (list_word.startsWith(ingredient)) {
            // If there is a match, add the word to the matchingWords array
            if (matchingWords.length < 5) {
                if (list_word != ingredient) {
                    matchingWords.push(wordList[i]);
                }
            }
        }
    }

    var autoCompleteHTML = "<ul>"
    for (i=0;i<matchingWords.length;i++) {
        autoCompleteHTML += "<li onclick=" + '"' + "select_autocomplete('" + matchingWords[i]  + "')" + '">' + matchingWords[i] + '</li>'
        // <li onclick="select_autocomplete('chicken')">chicken</li>
        console.log(matchingWords[i]);
    }
    autoCompleteHTML += "</ul>"
    console.log(autoCompleteHTML);
    // Filling up the list
    document.getElementById('autocomplete').innerHTML = autoCompleteHTML;
    if (ingredient == "") {
        close_list();
    }
}

// Allowing user to select the autocomplete function
function select_autocomplete(word) {
    var ingredient_input = document.getElementById('ingredient');
    var current_input = ingredient_input.value
    var arr = current_input.split(',');
    var allexceptLast = arr.slice(0, arr.length - 1);
    allexceptLast.push(word);

    document.getElementById('ingredient').value = allexceptLast.join(',');
    console.log('clicked selected');
    autocompletion();
}



// Close all lists when not targeted
function close_list(){
    document.getElementById('autocomplete').innerHTML = '';
}
document.addEventListener("click", function(e){
    if (e.target.id == 'ingredient') {
        autocompletion();
    }
    else {
        close_list();
    }
})



// Checking inputs before submitting recipe
function submit_recipe1() { 
    recipe_name_input = document.getElementById('name').value;
    recipe_instruction_input = document.getElementById('instructions').value;
    var regex = /^[a-zA-Z\s]+$/;
    if (regex.test(recipe_name_input)) {
        if (recipe_name_input.trim() == '') {
            document.getElementById('name').value = ''
        }
        if (recipe_instruction_input.trim() == '') {
            document.getElementById('instructions').value = '';
        }



        document.getElementById('ingredients').value = ingredient_list;
        document.getElementById('create_recipe_form').submit();
    }
    else {
        display_popup('Letters are only accepted for the name.', 'error');
    }
}
    
  
  
  // Sending POST request
  function search_ingredients() {
      document.getElementById('ingredient').value = ingredient_list;
  }

function add_ingredient_item(string1) {
    var ingredient = string1;
        if (ingredient.trim() == '') {
        display_popup('The input is empty.', 'error')
    }
    else {
        var regex = /^[a-zA-Z\s,]+$/;
        if (regex.test(ingredient)) {
            for (i=0;i<ingredient.length;i++) {
                if (ingredient_list.includes(ingredient)) {

                }
                else {
                    if (ingredient.trim() == '') {
                        display_popup('The input is empty.', 'error');
                    }
                    else {
                        ingredient_list.push(string1);
                        display_ingredient();
                    }
                }
            }
        }
        else {
            display_popup('Letters, spaces and commas are only accepted.', 'error');
        }
    }
}