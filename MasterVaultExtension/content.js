let notificationSent = false;

function addFocusListenerToPasswordInputs() {
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  passwordInputs.forEach(input => {
    input.addEventListener('focus', () => {
      if (!notificationSent) {
        chrome.runtime.sendMessage({ type: "PASSWORD_INPUT_FOCUSED" });
        notificationSent = true; // Set the flag so it doesn't send again until page refresh
      }
    });
  });
}

// Initially add listeners to any existing password inputs
addFocusListenerToPasswordInputs();

// Use a MutationObserver to detect new password inputs and add listeners to them
const observer = new MutationObserver(mutations => {
  mutations.forEach(mutation => {
    if (mutation.addedNodes.length) {
      addFocusListenerToPasswordInputs();
    }
  });
});

observer.observe(document.body, { childList: true, subtree: true });


// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'autofillPassword') {
        // Retrieve the generated password from storage
        chrome.storage.local.get('generatedPassword', function(result) {
            if (result.generatedPassword) {
                const password = result.generatedPassword;

                // Select all password fields (in case there are multiple)
                const passwordFields = document.querySelectorAll('input[type="password"]');

                if (passwordFields.length > 0) {
                    // Autofill the first password field found (or prompt user to select if multiple)
                    passwordFields.forEach(field => {
                        field.value = password;

                        // Trigger a 'change' event to simulate user input
                        const event = new Event('change', { bubbles: true });
                        field.dispatchEvent(event);
                    });

                    // Optionally send a success response
                    sendResponse({ status: 'success', message: 'Password autofilled.' });
                } else {
                    // No password field found on the page
                    alert('No password field found on this page.');
                    sendResponse({ status: 'error', message: 'No password field found.' });
                }
            } else {
                // No generated password available in storage
                alert('No generated password found in the extension.');
                sendResponse({ status: 'error', message: 'No generated password available.' });
            }
        });

        // Indicate that the response will be sent asynchronously
        return true;
    }
});









