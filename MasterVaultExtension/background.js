// chrome.runtime.onInstalled.addListener(() => {
//     // Create the context menu item for autofilling the password
//     chrome.contextMenus.create({
//         id: "autofillPassword", // This is the ID for the context menu
//         title: "MasterVault - Autofill Password", // The label users will see
//         contexts: ["editable"] // Ensures it only shows on editable fields
//     });
//
//     console.log("Autofill context menu created");
// });


// Listen for messages from the popup or other scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('Received message:', message);
    if (!message.action || !message.password || !message.tabId) {
        console.warn('Autofill failed. Invalid request: Missing action, password.');
        sendResponse({ status: 'Autofill failed. Invalid request: Missing action, password.' });
        return;
    }

    if (message.action === 'autofillPassword') {
        // Perform autofill on the specified tab
        autofillPassword(message.tabId, message.password);
        sendResponse({ status: 'Autofill attempted' });
    } else {
        console.warn('Autofill failed. Invalid request: Unknown action:', message.action);
        sendResponse({ status: 'Autofill failed. Invalid request: Unknown action.' });
    }
    return true;
});


// Autofill function to inject the password into the page
function autofillPassword(tabId, password) {
    chrome.scripting.executeScript({
        target: { tabId: tabId },
        function: (password) => {
            // Function to find the password field on the page
            function findPasswordField() {
                // Try common password field selectors
                let passwordField = document.querySelector('input[type="password"]')
                    || document.querySelector('input[name="pass"]')
                    || document.querySelector('input[autocomplete="current-password"]');

                // If still not found, check for other potential password fields
                if (!passwordField) {
                    passwordField = document.querySelector('input[type="password"][data-testid="royal_pass"]')
                        || document.querySelector('input[type="password"][id="pass"]');
                }

                if (!passwordField) {
                    let textFields = document.querySelectorAll('input[type="text"]');
                    for (let field of textFields) {
                        let fieldName = field.getAttribute('name') || '';
                        let fieldAutocomplete = field.getAttribute('autocomplete') || '';

                        // Avoid fields likely used for email or username
                        if (!fieldName.toLowerCase().includes('email') && !fieldAutocomplete.toLowerCase().includes('email')
                            && !fieldName.toLowerCase().includes('user') && !fieldAutocomplete.toLowerCase().includes('user')) {
                            passwordField = field;
                            break;
                        }
                    }
                }

                return passwordField;
            }

            // attempt autofilling the password
            function attemptAutofill() {
                const passwordField = findPasswordField();

                if (passwordField) {
                    // Set the value to the generated password
                    passwordField.value = password;

                    // If the field is currently a "text" input, change it back to "password" for security
                    if (passwordField.type === "text") {
                        passwordField.type = "password";
                    }

                    // Trigger input and change events to simulate user typing
                    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
                    passwordField.dispatchEvent(new Event('change', { bubbles: true }));

                    console.log("Password autofilled successfully.");
                    return true; // Indicate autofill success
                }
                return false; // Indicate autofill failure
            }

            const observer = new MutationObserver(() => {
                if (attemptAutofill()) {
                    // Stop observing once autofill succeeds
                    observer.disconnect();
                }
            });

            observer.observe(document.body, { childList: true, subtree: true });

            // Try to autofill immediately
            if (!attemptAutofill()) {
                console.log("Password field not found yet, waiting for changes...");
            } else {
                observer.disconnect();
            }
        },
        args: [password]
    });
}

