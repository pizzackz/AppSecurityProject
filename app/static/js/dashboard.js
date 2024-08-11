fetch('/admin/log/api/dashboard1')
  .then(response => response.json())
  .then(data => {
    const ctx = document.getElementById('chart1');

    // Use data.content to access the content list
    var log_list = data.content;

    // Construct the data for the chart
    var logData = {
      labels: [
        'Now', '2', '4', '6', '8',
        '10', '12', '14', '16', '18',
        '22', '24'
      ],
      datasets: [{
        label: 'User activities in the last 24 hours',
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
        responsive: true,
        scales: {
          x: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Last 24 Hours (visits grouped by every 2hrs)',  // X-axis label
              color: '#333',  // Y-axis label color
              font: {
                size: 16,     // Y-axis label font size
                weight: 'bold' // Y-axis label font weight
              }
            }
          },
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'User Visits',  // Y-axis label
              color: '#333',  // X-axis label color
              font: {
                size: 18,     // X-axis label font size
                weight: 'bold' // X-axis label font weight
              }
            }
          }
        }
      }
    });
  })
  .catch(error => {
    console.error('There was an error fetching the data:', error);
  });


//chart2
fetch('/admin/log/api/dashboard2')
  .then(response => response.json())
  .then(data => {
    const ctx = document.getElementById('chart2');

    // Use data.content to access the content list
    var log_list = data.content;

    // Construct the data for the chart
    var logData = {
      labels: [
        'Now', '2', '4', '6', '8',
        '10', '12', '14', '16', '18',
        '22', '24'
      ],
      datasets: [{
        label: 'Errors caught in the last 24 hours',
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
        responsive: true,
        scales: {
          x: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Last 24 Hours (errors grouped by every 2hrs)',  // X-axis label
              color: '#333',  // Y-axis label color
              font: {
                size: 16,     // Y-axis label font size
                weight: 'bold' // Y-axis label font weight
              }
            }
          },
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Errors',  // Y-axis label
              color: '#333',  // X-axis label color
              font: {
                size: 18,     // X-axis label font size
                weight: 'bold' // X-axis label font weight
              }
            }
          }
        }
      }
    });
  })
  .catch(error => {
    console.error('There was an error fetching the data:', error);
  });


//chart3
fetch('/admin/log/api/dashboard3')
  .then(response => response.json())
  .then(data => {
    const ctx = document.getElementById('chart3');

    // Use data.content to access the content list
    var log_list = data.content;

    // Construct the data for the chart
    var logData = {
      labels: [
        'Now', '2', '4', '6', '8',
        '10', '12', '14', '16', '18',
        '22', '24'
      ],
      datasets: [{
        label: 'Security incidents in the last 24 hours',
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
        responsive: true,
        scales: {
          x: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Last 24 Hours (incidents grouped by every 2hrs)',  // X-axis label
              color: '#333',  // Y-axis label color
              font: {
                size: 16,     // Y-axis label font size
                weight: 'bold' // Y-axis label font weight
              }
            }
          },
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Incidents',  // Y-axis label
              color: '#333',  // X-axis label color
              font: {
                size: 18,     // X-axis label font size
                weight: 'bold' // X-axis label font weight
              }
            }
          }
        }
      }
    });
  })
  .catch(error => {
    console.error('There was an error fetching the data:', error);
  });

//chart4
fetch('/admin/log/api/dashboard4')
  .then(response => response.json())
  .then(data => {
    const ctx = document.getElementById('chart4');

    // Use data.content to access the content list
    var log_list = data.content;

    // Construct the data for the chart
    var logData = {
      labels: [
        'Now', '2', '4', '6', '8',
        '10', '12', '14', '16', '18',
        '22', '24'
      ],
      datasets: [{
        label: 'Member account detail updates in the last 24 hours',
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
        responsive: true,
        scales: {
          x: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Last 24 Hours (Updates grouped by every 2hrs)',  // X-axis label
              color: '#333',  // Y-axis label color
              font: {
                size: 16,     // Y-axis label font size
                weight: 'bold' // Y-axis label font weight
              }
            }
          },
          y: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Updates',  // Y-axis label
              color: '#333',  // X-axis label color
              font: {
                size: 18,     // X-axis label font size
                weight: 'bold' // X-axis label font weight
              }
            }
          }
        }
      }
    });
  })
  .catch(error => {
    console.error('There was an error fetching the data:', error);
  });


