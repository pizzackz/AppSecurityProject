var ingredient_list = [];

// Loading document page
localStorageGet();
if (ingredient_list == null) {
    ingredient_list = [];
}

// Remove ingredient
function remove_ingredient(num) {
    ingredient_list.splice(num, 1);
    display_ingredient();
    localStorageStore();
}

// Display ingredient
function display_ingredient() {
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
    const form1 = document.getElementById('form1');
    const add_item = document.getElementById("add_ingredient");
    document.getElementById('ingredients').value = '';
    autocompletion();
    display_ingredient();
    add_item.addEventListener('click', function() { // Add event listener to adding ingredient button
        var ingredient = document.getElementById('ingredients').value;
        ingredient = ingredient.toLowerCase();
        if (ingredient.trim() == '') {
            display_popup('The input is empty.', 'error')
        }
        else {
            var regex = /^[a-zA-Z\s,]+$/;
            var arr = ingredient.split(',');
            if (regex.test(ingredient)) {
                for (i=0;i<arr.length;i++) {
                    if (ingredient_list.includes(arr[i])) {
                        display_popup(arr[i] + ' is already added.', 'error');
                    }
                    else {
                        if ((arr[i]).trim() == '') {
                            display_popup('The input is empty.', 'error');
                        }
                        else {
                            if (ingredient_list.length + 1 > 12) {
                                display_popup('Max ingredients are 12!', 'error');
                            }
                            else {
                                ingredient_list.push(arr[i]);
                                display_ingredient();
                                localStorageStore();
                            }
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
        localStorageStore();
    })
    const search = document.getElementById('search');
    search.addEventListener('click', search_ingredients);
    document.getElementById('recipe_items').addEventListener('click', function(event) {
    if (event.target.classList.contains('delete-button')) {
      var card = event.target.closest('.card');
      var recipeName = card.getAttribute('data-recipe-name');
      var recipeId = card.getAttribute('data-recipe-id');
      confirmdelete(recipeName, recipeId);
    }
  });
})

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
    var current_input = ingredient_input.value;
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


// Display popup
function hide_popup() {
    var popup = document.getElementById('popup');
    popup.classList.remove('show1');
    popup.classList.add('hide');
}

// Checking ingredient list before sending POST request 
function search_ingredients() {
    console.log(ingredient_list)
    if (ingredient_list.length == 0) {
        display_popup('Ingredient list is empty!', 'error');
    }
    if (ingredient_list.length > 12) {
        display_popup('Max ingredients is 12!', 'error');
    }
    else {
        document.getElementById('ingredients').value = ingredient_list;
        document.getElementById('form1').submit();
    }
}
// Local Storage
function localStorageStore() {
    const jsonString = JSON.stringify(ingredient_list);
    const key = "ArrayData";
    localStorage.setItem(key,jsonString); 
}
function localStorageGet() {
    const key = "ArrayData";
    const jsonString = localStorage.getItem(key);
    ingredient_list = JSON.parse(jsonString);
}

// Activate overlay
function overlayon() {
    const overlay = document.getElementById('overlay');
    overlay.style.display = 'block';
}
function overlayoff() {
    const overlay = document.getElementById('overlay');
    overlay.style.display = 'none';
}

function confirmdelete(content, id) {
    console.log(content);
    document.getElementById('modal-body').innerHTML = 'Are you sure you want to remove ' + content + '?';
    document.getElementById('delete').onclick = function () {
      window.location.href = "delete_recipe/" + id;
    }
}

