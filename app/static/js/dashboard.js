fetch('/admin/log/api/performance')
  .then(response => response.json())
  .then(data => {
    const ctx = document.getElementById('myChart');

    // Use data.content to access the content list
    var log_list = data.content;

    // Construct the data for the chart
    var logData = {
      labels: [
        '24 hours ago', '22 hours ago', '20 hours ago', '18 hours ago', '16 hours ago',
        '14 hours ago', '12 hours ago', '10 hours ago', '8 hours ago', '6 hours ago',
        '4 hours ago', '2 hour ago'
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

























// // document.addEventListener('DOMContentLoaded', function() {
//     var ctx = document.getElementById('performanceChart');
//     var performanceChart = new Chart(ctx, {
//         type: 'line',
//         data: {
//             labels: ['12 hour ago', '11 hours ago', '10 hours ago', '9 hours ago', '8 hours ago',
//                         '7 hours ago', '6 hours ago', '5 hours ago', '4 hours ago', '3 hours ago',
//                         '2 hours ago', '1 hour ago'], // Time labels
//             datasets: [{
//                 label: 'Requests per Second',
//                 logdata: [],
//                 borderColor: 'rgba(75, 192, 192, 1)',
//                 backgroundColor: 'rgba(75, 192, 192, 0.2)',
//                 fill: false,
//             }]
//         },



//         var recipesChart = new Chart(ctx, {
//             type: 'line',
//             data: logData,
//             options: {
//                 scales: {
//                     y: {
//                         beginAtZero: true
//                     }
//                 }
//             }
//         });
//         options: {
//             responsive: true,
//             scales: {
//                 x: {
//                     type: 'time',
//                     time: {
//                         unit: 'second',
//                         tooltipFormat: 'HH:mm:ss'
//                     },
//                     title: {
//                         display: true,
//                         text: 'Time'
//                     }
//                 },
//                 y: {
//                     beginAtZero: true,
//                     title: {
//                         display: true,
//                         text: 'Requests per Second'
//                     }
//                 }
//             }
//         }
//     });

//     // // Function to generate fake data
//     // function generateFakeData() {
//     //     const now = new Date();
//     //     let labels = [];
//     //     let data = [];
//     //     for (let i = 0; i < 20; i++) {
//     //         labels.push(new Date(now.getTime() - (20 - i) * 1000));
//     //         data.push(Math.floor(Math.random() * 100) + 50); // Fake data between 50 and 150
//     //     }
//     //     return { labels, data };
//     // }

//     // // Populate the chart with fake data
//     // const fakeData = generateFakeData();
//     // performanceChart.data.labels = fakeData.labels;
//     // performanceChart.data.datasets[0].data = fakeData.data;
//     // performanceChart.update();

//     // Update chart with real data periodically
//     function updateChart() {
//         fetch('/api/performance')
//     .then(response => response.json())
//     .then(data => {
//         const ctx = document.getElementById('myChart');
//         var jsonData = await response.json()
//         var log_list = jsonData.content
//         var logData = {
//                 labels: [
//                     '12 hour ago', '11 hours ago', '10 hours ago', '9 hours ago', '8 hours ago',
//                     '7 hours ago', '6 hours ago', '5 hours ago', '4 hours ago', '3 hours ago',
//                     '2 hours ago', '1 hour ago'
//                 ],
//                 datasets: [{
//                     label: 'User activities in the last 12 hours',
//                     data: log_list,
//                     backgroundColor: 'rgba(75, 192, 192, 0.2)',
//                     borderColor: 'rgba(75, 192, 192, 1)',
//                     borderWidth: 1
//                 }]
//             };
//         var myChart = new Chart(ctx, {
//             type: 'line',
//             data: logData,
//             options: {
//                 scales: {
//                     y: {
//                         beginAtZero: true
//                     }
//                 }
//             }
//         });
//     });

// //                 performanceChart.update();
// //             })
// //             .catch(error => console.error('Error fetching performance data:', error));
// //     }

// //     setInterval(updateChart, 1000); // Update every second
// // });

// // // Define the API endpoint URL
// // const apiUrl = 'https://api.example.com/data';

// // // Use the fetch function to make a GET request
// // fetch(apiUrl)
// //   .then(response => {
// //     // Check if the request was successful
// //     if (!response.ok) {
// //       throw new Error('Network response was not ok ' + response.statusText);
// //     }
// //     // Parse the JSON from the response
// //     return response.json();
// //   })
// //   .then(data => {
// //     // Use the data from the API
// //     console.log(data);
// //   })
// //   .catch(error => {
// //     // Handle errors
// //     console.error('There was a problem with the fetch operation:', error);
// //   });