function showSection(sectionId) {
    // Hide all sections
    const sections = document.querySelectorAll('section');
    sections.forEach(section => {
        section.style.display = 'none';
    });

    // Show the selected section
    document.getElementById(sectionId).style.display = 'block';
}

// Real-time search functionality
document.getElementById('searchBar').addEventListener('keyup', function() {
    const query = this.value.trim(); // Get the search query and remove leading/trailing spaces

    // Create an AJAX request
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

    // Send the request with the search query
    xhr.send('query=' + encodeURIComponent(query));

    // Handle the response
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4 && xhr.status == 200) {
            // Update the user list table body with the response
            document.getElementById('userList').innerHTML = xhr.responseText;
        }
    };
});

document.getElementById('filterRole').addEventListener('change', function() {
const query = document.getElementById('searchBar').value;
const role = this.value;

// Create an AJAX request
const xhr = new XMLHttpRequest();
xhr.open('POST', '', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

// Send the request with the search query and selected role
xhr.send('query=' + encodeURIComponent(query) + '&role=' + encodeURIComponent(role));

// Handle the response
xhr.onreadystatechange = function() {
    if (xhr.readyState == 4 && xhr.status == 200) {
        // Update the user list table body with the response
        document.getElementById('userList').innerHTML = xhr.responseText;
    }
};
});

document.addEventListener('DOMContentLoaded', function() {
var closeButtons = document.querySelectorAll('.close-alert');
var alerts = document.querySelectorAll('.alert');

// Automatically fade out the alert after 5 seconds (5000 ms)
setTimeout(function() {
    alerts.forEach(function(alert) {
        alert.style.opacity = '0'; // Start fade out

        // After the fade-out transition, set display to none
        setTimeout(function() {
            alert.style.display = 'none';
        }, 1000); // Match this duration with the CSS transition duration (1 second)
    });
}, 5000);

// Allow manual closing of the alert
closeButtons.forEach(function(button) {
    button.addEventListener('click', function() {
        var alert = this.parentElement;
        alert.style.opacity = '0'; // Start fade out
        setTimeout(function() {
            alert.style.display = 'none';
        }, 1000); // Match this duration with the CSS transition duration (1 second)
    });
});
});

document.addEventListener('DOMContentLoaded', function() {
    // Handle the edit button click with event delegation
    document.querySelector('#userList').addEventListener('click', function(event) {
        if (event.target && event.target.classList.contains('edit-user-btn')) {
            var button = event.target;
            var username = button.getAttribute('data-username');
            var role = button.getAttribute('data-role');
            var status = button.getAttribute('data-status');

            // Populate the modal fields with the user data
            document.getElementById('editOriginalUsername').value = username;
            document.getElementById('usernames').value = username;
            document.getElementById('editRole').value = role;
            document.getElementById('editStatus').value = status;
        }
    });
});
