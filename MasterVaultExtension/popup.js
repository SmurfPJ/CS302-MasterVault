document.addEventListener('DOMContentLoaded', function() {
    // Load saved settings (phrase and checkbox states) on extension load
    loadSavedSettings();

    // Check for existing user session
    checkActiveSession();

    // Register link: Open registration in a new tab
    var registerLink = document.getElementById('registerLink');
    if (registerLink) {
        registerLink.addEventListener('click', function(e) {
            e.preventDefault(); // Prevent default behavior
            var url = this.href;
            chrome.tabs.create({ url: url }); // Open in a new tab
        });
    }

    // Handle login
    document.getElementById('loginBtn').addEventListener('click', function(event) {
        event.preventDefault(); // Prevent form from submitting
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        fetch('http://127.0.0.1:5000/extension_login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ email: email, password: password })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json(); // Parse the response as JSON
        })
        .then(data => {
            if (data.status === 'success') {
                // Store session in Chrome local storage
                chrome.storage.local.set({ 'userSession': data });

                // Hide login form and show password generator
                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('passwordGenerator').style.display = 'block';

                // Display logged-in user's username
                document.getElementById('loggedInAs').innerText = `Logged in as: ${data.username}`;
            } else {
                document.getElementById('loginError').innerText = data.message;
            }
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('loginError').innerText = 'An error occurred. Please try again later.';
        });
    });

    // Handle logout
    document.getElementById('logoutBtn').addEventListener('click', function() {
        chrome.storage.local.remove('userSession', function() {
            // Clear session and display login form again
            document.getElementById('passwordGenerator').style.display = 'none';
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('loginError').innerText = ''; // Clear any error message
        });
    });

    // Save phrase input when it changes
    document.getElementById('phrase-input').addEventListener('input', function() {
        const phrase = this.value;
        chrome.storage.local.set({ 'savedPhrase': phrase });
    });

    // Save length input when it changes
    document.getElementById('length-input').addEventListener('input', function() {
        const length = this.value;
        chrome.storage.local.set({ 'savedLength': length });
    });

    // Save checkbox states when they change
    const checkboxes = ['replace_vowels', 'exclude_numbers', 'exclude_symbols', 'randomize'];
    checkboxes.forEach(function(id) {
        document.getElementById(id).addEventListener('change', function() {
            chrome.storage.local.set({ [id]: this.checked });
        });
    });

    // Handle password generation
    document.getElementById('generate-btn').addEventListener('click', function() {
        const phrase = document.getElementById('phrase-input').value;
        const length = parseInt(document.getElementById('length-input').value);
        const replaceVowels = document.getElementById('replace_vowels').checked;
        const excludeNumbers = document.getElementById('exclude_numbers').checked;
        const excludeSymbols = document.getElementById('exclude_symbols').checked;
        const randomize = document.getElementById('randomize').checked;

        let password = generatePassword(phrase, length, replaceVowels, excludeNumbers, excludeSymbols, randomize);
        document.getElementById('generated-password').value = password;

        // Store the generated password in chrome local storage
        chrome.storage.local.set({ 'generatedPassword': password });

        let strength = checkPasswordStrength(password);
        updateStrengthIndicator(strength);
    });

    // Handle dynamic updating of length input based on phrase input
    const phraseInput = document.getElementById('phrase-input');
    if (phraseInput) {
        phraseInput.addEventListener('input', updateLengthInput);
    }

    // Handle password input change and update strength indicator dynamically
    document.getElementById('passwordInput')?.addEventListener('input', handlePasswordInput);

    // Attach event listeners for refresh and copy buttons
    document.getElementById('refreshButton')?.addEventListener('click', refreshPasswordExtension);
    document.getElementById('clipboard-button')?.addEventListener('click', copyToClipboardExtension);


    const refreshButton = document.querySelector('.refreshButton');
    if (refreshButton) {
        refreshButton.addEventListener('click', refreshPasswordExtension);
    }
});

// load saved settings from chrome storage
function loadSavedSettings() {
    // Load the saved phrase and checkbox states
    chrome.storage.local.get(['savedPhrase', 'savedLength', 'replace_vowels', 'exclude_numbers', 'exclude_symbols', 'randomize'], function(result) {
        if (result.savedPhrase) {
            document.getElementById('phrase-input').value = result.savedPhrase;
        }

        if (result.savedLength) {
            document.getElementById('length-input').value = result.savedLength;
        }

        // Restore checkbox states
        if (result.replace_vowels !== undefined) {
            document.getElementById('replace_vowels').checked = result.replace_vowels;
        }
        if (result.exclude_numbers !== undefined) {
            document.getElementById('exclude_numbers').checked = result.exclude_numbers;
        }
        if (result.exclude_symbols !== undefined) {
            document.getElementById('exclude_symbols').checked = result.exclude_symbols;
        }
        if (result.randomize !== undefined) {
            document.getElementById('randomize').checked = result.randomize;
        }
    });
}

// Function to dynamically update the length input based on the phrase input
window.updateLengthInput = function () {
    const phraseInput = document.getElementById('phrase-input');
    const lengthInput = document.getElementById('length-input');

    const phrase = phraseInput.value;
    const minLength = phrase.replace(/\s+/g, '').length;
    lengthInput.value = minLength;

    chrome.storage.local.set({ 'savedLength': minLength });
};

// Autofill the generated password into the password field on the active tab
window.autofillPasswordExtension = function () {
    const generatedPasswordField = document.getElementById('generated-password');

    // Get the generated password value
    const password = generatedPasswordField.value;

    if (!password) {
        alert('No generated password to autofill.');
        return;
    }

    // Get the active tab and send a message to the background script to autofill the password
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
        if (tabs[0] && tabs[0].id) {
            const tabId = tabs[0].id;
            console.log('Sending autofill message:', { action: 'autofillPassword', password: password, tabId: tabId });
            chrome.runtime.sendMessage({ action: 'autofillPassword', password: password, tabId: tabId }, function(response) {
                // Check if there was an error sending the message
                if (chrome.runtime.lastError) {
                    console.error('Error sending message:', chrome.runtime.lastError.message);
                    return;
                }

                // Ensure the response is defined before accessing its properties
                if (response && response.status) {
                    console.log('Response from background script:', response.status);
                } else {
                    console.error('No response received or response is undefined.');
                }
            });
        } else {
            console.error('No active tab found.');
        }
    });
};

// Add event listener for the autofill icon
document.getElementById('autofill-icon').addEventListener('click', function() {
    autofillPasswordExtension();
});




// Handle the refresh button (refreshes the generated password)
window.refreshPasswordExtension = function () {
    const phraseInput = document.getElementById('phrase-input');
    const lengthInput = document.getElementById('length-input');
    const generatedPasswordField = document.getElementById('generated-password');
    const excludeNumbersCheckbox = document.getElementById('exclude_numbers');
    const excludeSymbolsCheckbox = document.getElementById('exclude_symbols');
    const replaceVowelsCheckbox = document.getElementById('replace_vowels');
    const randomizeCheckbox = document.getElementById('randomize');

    const phrase = phraseInput.value;
    const length = parseInt(lengthInput.value, 10);
    const excludeNumbers = excludeNumbersCheckbox.checked;
    const excludeSymbols = excludeSymbolsCheckbox.checked;
    const replaceVowels = replaceVowelsCheckbox.checked;
    const randomize = randomizeCheckbox.checked;

    if (!phrase || length < phrase.replace(/\s+/g, '').length) {
        generatedPasswordField.value = "Error: Check phrase length.";
        updateStrengthIndicator({ status: "Weak", score: 0, color: "red" });
        return;
    }

    // Generate the password with exclusions set by users
    const newPassword = generatePassword(phrase, length, replaceVowels, excludeNumbers, excludeSymbols, randomize);
    generatedPasswordField.value = newPassword;

    // Store the generated password in storage
    chrome.storage.local.set({ 'generatedPassword': newPassword });

    // Update password strength after refreshing
    const strength = checkPasswordStrength(newPassword);
    updateStrengthIndicator(strength);
};

// generate the password based on the user's inputs with phoneme replacements
function generatePassword(phrase, length, replaceVowels, excludeNumbers, excludeSymbols, randomize) {
    // Remove spaces from the phrase
    phrase = phrase.replace(/\s+/g, '');

    if (!phrase || length < phrase.length) return "";

    // Extended vowel map with phoneme-based replacements
    if (replaceVowels) {
        const vowelMap = {
            'a': ['@', 'A', 'æ', '4', 'â', 'ä'],
            'e': ['3', 'E', '€', 'ê', 'é', 'ë'],
            'i': ['1', 'I', '!', 'î', 'ï', 'í'],
            'o': ['0', 'O', 'ø', 'ô', 'ö', 'ó'],
            'u': ['U', 'u', 'ù', 'û', 'ü', 'ú']
        };

        // Replace vowels in the phrase based on the extended vowel map
        phrase = phrase.split('').map(function (char) {
            return vowelMap[char.toLowerCase()] ?
                vowelMap[char.toLowerCase()][Math.floor(Math.random() * vowelMap[char.toLowerCase()].length)]
                : char;
        }).join('');
    }

    // Remove numbers and symbols from the phrase if they are excluded
    if (excludeNumbers) {
        phrase = phrase.replace(/[0-9]/g, ''); // Remove all digits
    }
    if (excludeSymbols) {
        phrase = phrase.replace(/[!@#$%^&*()_\-+=<>?/[\]{}|]/g, ''); // Remove symbols
    }

    // Randomize the phrase characters if the option is selected
    if (randomize) {
        phrase = phrase.split('').sort(() => 0.5 - Math.random()).join('');
    }

    // Prevent extra characters from being added by trimming the phrase to the desired length
    let password = phrase.slice(0, length);

    return password;
}

// Function to check password strength and return strength details
function checkPasswordStrength(password) {
    let strength = { status: 'Weak', score: 0, color: 'red' };

    // Check if password is empty or undefined
    if (!password) {
        return strength;
    }

    // Length check: reward longer passwords
    if (password.length >= 15) {
        strength.score += 2;
    } else if (password.length >= 12) {
        strength.score += 1.5;
    } else if (password.length >= 8) {
        strength.score += 1;
    } else {
        strength.score += 0.5;
    }

    // Check for digits
    if (/\d/.test(password)) {
        strength.score += 1;
    }

    // Check for uppercase and lowercase combination
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) {
        strength.score += 1;
    }

    // Check for special characters (symbols)
    if (/[^A-Za-z0-9]/.test(password)) {
        strength.score += 1;
    }

    // Check for a mix of letters, numbers, and symbols
    if ((/[A-Za-z]/.test(password)) && (/\d/.test(password) || /[^A-Za-z0-9]/.test(password))) {
        strength.score += 1;
    }

    // Penalize for common patterns like "123", "password", "abc", "qwerty"
    const commonPatterns = ['123', 'password', 'abc', 'qwerty'];
    if (commonPatterns.some(pattern => password.toLowerCase().includes(pattern))) {
        strength.score -= 1;
    }

    // Penalize for consecutive identical characters
    if (/(.)\1\1/.test(password)) {
        strength.score -= 1;
    }

    // Penalize for too many repeated characters
    const charCounts = {};
    for (const char of password) {
        charCounts[char] = (charCounts[char] || 0) + 1;
    }
    const maxCount = Math.max(...Object.values(charCounts));
    if (maxCount > password.length / 2) {
        strength.score -= 1;
    }

    // make sure score is not negative
    strength.score = Math.max(0, strength.score);

    // Determine the status and color based on the score
    if (strength.score >= 5) {
        strength.status = 'Very Strong';
        strength.color = 'green';
    } else if (strength.score >= 4) {
        strength.status = 'Strong';
        strength.color = 'lightgreen';
    } else if (strength.score >= 3) {
        strength.status = 'Moderate';
        strength.color = 'orange';
    } else {
        strength.status = 'Weak';
        strength.color = 'red';
    }

    return strength;
}

// update the password strength indicator on the UI
function updateStrengthIndicator(strength) {
    const indicator = document.getElementById('strength-indicator');
    indicator.innerHTML = `
        <div class="progress" style="height: 20px;">
            <div class="progress-bar" role="progressbar" style="width: ${Math.min(strength.score * 20, 100)}%; background-color: ${strength.color};" aria-valuenow="${strength.score}" aria-valuemin="0" aria-valuemax="5"></div>
        </div>
        <p class="mt-2">${strength.status}</p>
    `;
}

// Check for an active session on extension load
function checkActiveSession() {
    chrome.storage.local.get(['userSession', 'generatedPassword'], function(result) {
        if (result.userSession && result.userSession.status === 'success') {
            // User is logged in, show password generator
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('passwordGenerator').style.display = 'block';
            document.getElementById('loggedInAs').innerHTML = 'Logged in as <strong>' + result.userSession.username + '</strong>';

            // If a password was previously generated, restore it
            if (result.generatedPassword) {
                document.getElementById('generated-password').value = result.generatedPassword;

                // Update strength indicator based on the restored password
                let strength = checkPasswordStrength(result.generatedPassword);
                updateStrengthIndicator(strength);
            }
        } else {
            // No session found, show login form
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('passwordGenerator').style.display = 'none';
        }
    });
}

