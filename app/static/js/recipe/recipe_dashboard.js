const ctx = document.getElementById('myChart')



const recipesChart = new Chart(ctx, {
    type: 'line',
    data: recipeData,
    options: {
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});