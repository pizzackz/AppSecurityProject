var ingredient_list = [];

// Loading document page
if (ingredient_list == null) {
    ingredient_list = [];
}

// Remove ingredient
function remove_ingredient(num) {
    ingredient_list.splice(num, 1);
    display_ingredient();
}


// Display ingredient
function display_ingredient() {
//    localStorageStore();
    var ingredient_itemHTML = "";
    for (let i = 0; i < ingredient_list.length; i++) {
        ingredient_itemHTML +=
            '<div class="ingredient_item" id="' +
            ingredient_list[i] +
            `" style="width:fit-content">
                <i class="bi bi-x remove_ingredient" data-index="${i}" aria-label="Remove Ingredient"></i>
                <span class="item">` +
            ingredient_list[i] +
            "</span></div>";
    }
    document.getElementById("ingredient_items_list").innerHTML = ingredient_itemHTML;

    // Event delegation
    document.getElementById("ingredient_items_list").addEventListener("click", function (event) {
        if (event.target && event.target.matches("i.remove_ingredient")) {
            const index = event.target.getAttribute("data-index");
            remove_ingredient(index);
        }
    });

    const remove_all = document.getElementById("remove_all");
    if (ingredient_itemHTML !== "") {
        remove_all.classList.remove("disabled");
    } else {
        remove_all.classList.add("disabled");
    }
}

// Add event listeners to buttons
document.addEventListener("DOMContentLoaded", function() {
//    localStorageGet();
    const form1 = document.getElementById('form1');
    const add_item = document.getElementById("add_ingredient");
    display_ingredient();
    autocompletion();
    tinymce.init({
        selector: '#instructions',
        toolbar: 'undo redo | bold italic underline',
        menubar: 'file edit view'
    })
    add_item.addEventListener('click', function() { // Add event listener to adding ingredient button
        var ingredient = document.getElementById('ingredients').value;
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
})

// Display popup
function hide_popup() {
    var popup = document.getElementById('popup');
    popup.classList.remove('show1');
    popup.classList.add('hide');
}

// Ingredient input autocomplete
var ingredient_input = document.getElementById('ingredients');

function autocompletion() {
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
        // Check if the word starts with the entered ingredient
        if (list_word.startsWith(ingredient)) {
            if (matchingWords.length < 5 && list_word !== ingredient) {
                matchingWords.push(list_word);
            }
        }
    }

    var autoCompleteHTML = "<ul>";
    for (let i = 0; i < matchingWords.length; i++) {
        autoCompleteHTML += "<li data-word='" + matchingWords[i] + "'>" + matchingWords[i] + '</li>';
    }
    autoCompleteHTML += "</ul>";

    // Filling up the list
    const autocompleteElement = document.getElementById('autocomplete');
    autocompleteElement.innerHTML = autoCompleteHTML;

    // Event delegation for clicks
    autocompleteElement.addEventListener('click', function(event) {
        if (event.target && event.target.matches("li[data-word]")) {
            const selectedWord = event.target.getAttribute('data-word');
            select_autocomplete(selectedWord);
        }
    });

    if (ingredient == "") {
        close_list();
    }
}


// Allowing user to select the autocomplete function
function select_autocomplete(word) {
    var current_input = ingredient_input.value
    var arr = current_input.split(',');
    var allexceptLast = arr.slice(0, arr.length - 1);
    allexceptLast.push(word);

    document.getElementById('ingredients').value = allexceptLast.join(',');
    console.log('clicked selected');
    autocompletion();
}

ingredient_input.addEventListener('input', autocompletion);

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
  recipe_instruction_input = tinymce.get('instructions').getContent();
  file_input = document.getElementById('picture');
  file = file_input.files;

  if (file.length == 0) {
    display_popup('No file uploaded', 'error')
  }
  else {
    console.log(recipe_name_input, recipe_instruction_input);
    if (ingredient_list == []) {
      display_popup('Ingredient list is empty!', 'error')
    }
    var regex = /^[a-zA-Z\s]+$/;
    if (recipe_name_input.trim() == '') {
      display_popup('Empty inputs.', 'error')
    }
    else {
      if (recipe_instruction_input.trim() == '') {
        display_popup('Empty inputs.', 'error');
      }
      else {
        if (regex.test(recipe_name_input)) {
            document.getElementById('ingredients').value = ingredient_list;
            document.getElementById('create_recipe_form').submit();
        }
        else {
            display_popup('Letters are only accepted for the name.', 'error');
        }
      }
    }
  }
}

var submit_button = document.getElementById('submit_button');
submit_button.addEventListener('click', function() {
  submit_recipe1();
})

// Local Storage
//function localStorageStore() {
//    if (ingredient_list == null) {
//        ingredient_list = [];
//    }
//    const jsonString = JSON.stringify(ingredient_list);
//    const key = "ingredients";
//    localStorage.setItem(key,jsonString);
//
//    const name = document.getElementById('name').value;
//    const instructions = document.getElementById('instructions').value;
//    const calories = document.getElementById('calories').value;
//    const prep_time = document.getElementById('prep_time').value;
//    const recipe_type = document.getElementById('type').value;
//
//    const recipe_info = {
//        name: name,
//        instructions: instructions,
//        calories: calories,
//        prep_time: prep_time,
//        recipe_type: recipe_type
//    }
//    const recipe_info_string = JSON.stringify(recipe_info);
//    const recipe_key = "recipe_info";
//    localStorage.setItem(recipe_key, recipe_info_string);
//}
//function localStorageGet() {
//    const key = "ingredients";
//    const jsonString = localStorage.getItem(key);
//    ingredient_list = JSON.parse(jsonString);
//
//    const recipe_key = "recipe_info";
//    const recipe_info_string = localStorage.getItem(recipe_key);
//    const recipe_info = JSON.parse(recipe_info_string);
//
//    if (recipe_info != null) {
//        document.getElementById('name').value = recipe_info.name;
//        tinymce.get('instructions').setContent(recipe_info.instructions);
//        document.getElementById('calories').value = recipe_info.calories;
//        document.getElementById('prep_time').value = recipe_info.prep_time;
//        document.getElementById('recipe_type').value = recipe_info.recipe_type;
//    }
//}
//
//document.getElementById('name').addEventListener('input', localStorageStore);
//document.getElementById('calories').addEventListener('input', localStorageStore);
//document.getElementById('prep_time').addEventListener('input', localStorageStore);
//document.getElementById('type').addEventListener('input', localStorageStore);
//document.getElementById('instructions').addEventListener('input', localStorageStore);





