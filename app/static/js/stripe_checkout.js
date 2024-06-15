var stripe = Stripe('{{ publishable_key }}');
var checkoutButton = document.getElementById('checkout-button');

checkoutButton.addEventListener('click', function () {
  fetch('/create-checkout-session', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': '{{ csrf_token() }}'
    },
  })
  .then(function (response) {
    return response.json();
  })
  .then(function (session) {
    return stripe.redirectToCheckout({ sessionId: session.id });
  })
  .then(function (result) {
    if (result.error) {
      alert(result.error.message);
    }
  })
  .catch(function (error) {
    console.error('Error:', error);
  });
});

var returnButton = document.getElementById("return-button");
returnButton.addEventListener("click", function() {
  window.history.back();
});