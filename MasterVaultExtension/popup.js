chrome.storage.onChanged.addListener(function(changes, namespace) {
    for (var key in changes) {
        var storageChange = changes[key];
        if (key === 'userSession' && namespace === 'local') {
            // Check if the user is logged in
            if (storageChange.newValue && storageChange.newValue.status === 'success') {
                // User is logged in, update UI accordingly
                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('passwordGenerator').style.display = 'block';
                document.getElementById('loggedInAs').innerHTML = 'Logged in as <strong>' + storageChange.newValue.username + '</strong>';
            } else {
                // No user session, show login form
                document.getElementById('loginForm').style.display = 'block';
                document.getElementById('passwordGenerator').style.display = 'none';
            }
        }
    }
});

document.addEventListener('DOMContentLoaded', function() {
    var registerLink = document.getElementById('registerLink');
    if (registerLink) {
        registerLink.addEventListener('click', function(e) {
            e.preventDefault(); // Prevent the default link behavior
            var url = this.href;
            chrome.tabs.create({ url: url }); // Open the link in a new tab
        });
    }

    // Handle login
    document.getElementById('loginBtn').addEventListener('click', function() {
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        fetch('http://127.0.0.1:5000/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ email: email, password: password })
        })
        .then(response => response.json())
        .then(data => {console.log(email)
            if (data.status === 'success') {
                chrome.storage.local.set({ 'userSession': data });
            } else {
                document.getElementById('loginError').innerText = data.message;
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });

    // Handle logout
    document.getElementById('logoutBtn').addEventListener('click', function() {
        chrome.storage.local.remove('userSession', function() {
            document.getElementById('passwordGenerator').style.display = 'none';
            document.getElementById('loginForm').style.display = 'block';
        });
    });

    // Password generation logic
    document.getElementById('generate-btn').addEventListener('click', function() {
        const phrase = document.getElementById('phrase-input').value;
        const length = parseInt(document.getElementById('length-input').value);
        const replaceVowels = document.getElementById('replace_vowels').checked;
        const excludeNumbers = document.getElementById('exclude_numbers').checked;
        const excludeSymbols = document.getElementById('exclude_symbols').checked;
        const randomize = document.getElementById('randomize').checked;

        let password = generatePassword(phrase, length, replaceVowels, excludeNumbers, excludeSymbols, randomize);
        document.getElementById('generated-password').value = password;

        let strength = checkPasswordStrength(password);
        updateStrengthIndicator(strength);
    });

    function generatePassword(phrase, length, replaceVowels, excludeNumbers, excludeSymbols, randomize) {
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (!excludeNumbers) characters += "0123456789";
        if (!excludeSymbols) characters += "!@#$%^&*()_-+=<>?/[]{}|";

        let password = "";
        for (let i = 0; i < length; i++) {
            password += characters.charAt(Math.floor(Math.random() * characters.length));
        }

        // Add additional logic to handle replacements and randomization
        if (replaceVowels) {
            password = password.replace(/[aeiou]/gi, '*');  // Example replacement
        }

        return password;
    }

    function checkPasswordStrength(password) {
        var strength = {status: 'Weak', score: 0, color: 'red'};

        if (password.length >= 8) strength.score += 1;
        if (/[0-9]/.test(password)) strength.score += 1;
        if (/[A-Z]/.test(password)) strength.score += 1;
        if (/[^A-Za-z0-9]/.test(password)) strength.score += 1;

        if (strength.score === 4) {
            strength.status = 'Very Strong';
            strength.color = 'green';
        } else if (strength.score === 3) {
            strength.status = 'Strong';
            strength.color = 'lightgreen';
        } else if (strength.score === 2) {
            strength.status = 'Moderate';
            strength.color = 'orange';
        }

        return strength;
    }

    function updateStrengthIndicator(strength) {
        const indicator = document.getElementById('strength-indicator');
        indicator.innerHTML = `
            <div class="progress" style="height: 20px;">
                <div class="progress-bar" role="progressbar" style="width: ${strength.score * 25}%; background-color: ${strength.color};" aria-valuenow="${strength.score}" aria-valuemin="0" aria-valuemax="4"></div>
            </div>
            <p class="mt-2">${strength.status}</p>
        `;
    }
});


