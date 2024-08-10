const ctx = document.getElementById('myChart')

fetch('/api/recipe_info')
  .then(response => response.json())
  .then(data => {
    var log_list = data.content;
    var logData = {
      labels: [
        '12 hours ago', '11 hours ago', '10 hours ago', '9 hours ago', '8 hours ago',
        '7 hours ago', '6 hours ago', '5 hours ago', '4 hours ago', '3 hours ago',
        '2 hours ago', '1 hour ago'
      ],
      datasets: [{
        label: 'Recipes Created in the last 12 hours',
        data: log_list,
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        borderColor: 'rgba(75, 192, 192, 1)',
        borderWidth: 1
      }]
    };

    // Initialize the chart
    var myChart = new Chart(ctx, {
      type: 'line',
      data: logData,
      options: {
        scales: {
          y: {
            beginAtZero: true
          }
        }
      }
    });
  })
  .catch(error => {
    console.error('There was an error fetching the data:', error);
  });

document.addEventListener("DOMContentLoaded", function() {
    document.addEventListener("click", function(event) {
        if (event.target.classList.contains('delete-button')) {
            var button = event.target;
            var name = button.getAttribute('data-delete-name');
            var href = button.getAttribute('data-delete');
            confirmdelete(name, href);
        }
    });
});

function confirmdelete(name, href) {
    document.getElementById('modal-body').innerHTML = 'Are you sure you want to delete ' + name + '?';
    document.getElementById('delete').onclick = function() {
        window.location.href = href
    }
}