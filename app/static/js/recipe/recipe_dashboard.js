const ctx = document.getElementById('myChart')

// Jacen's part: Fetch data from endpoint api/performance, data is in JSON format
// Fetch data from endpoint api/performance, data is in JSON format
fetch('/api/recipe_info')
  .then(response => response.json())
  .then(data => {

    // Use data.content to access the content list
    var log_list = data.content;

    // Construct the data for the chart
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