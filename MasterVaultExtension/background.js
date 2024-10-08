// chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
//   if (message.type === "PASSWORD_INPUT_FOCUSED") {
//     const notificationId = `password-focused-${Date.now()}`;
//
//     chrome.notifications.create(notificationId, {
//       type: 'basic',
//       iconUrl: 'images/Logo16x16.png',
//       title: 'MasterVault',
//       message: 'A reminder to secure your passwords using our password generator!',
//       priority: 2
//     });
//   }
// });

// Create a context menu item for password fields
// Context Menu Setup
chrome.runtime.onInstalled.addListener(() => {
    // Create the context menu item for autofilling the password
    chrome.contextMenus.create({
        id: "autofillPassword", // This is the ID for the context menu
        title: "MasterVault - Autofill Password", // The label users will see
        contexts: ["editable"] // Ensures it only shows on editable fields
    });

    console.log("Autofill context menu created");
});

// Handle context menu click
chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "autofillPassword") {
        // Autofill the password when the user clicks the context menu
        chrome.storage.local.get('userSession', function(result) {
            if (result.userSession && result.userSession.status === 'success') {
                // If logged in, autofill the password
                autofillPassword(tab.id);
            } else {
                // If not logged in, open the extension login page in a popup
                chrome.windows.create({
                    url: "popup.html",
                    type: "popup",
                    width: 400,
                    height: 600
                });
            }
        });
    }
});

// Autofill function to be injected into the page
function autofillPassword(tabId) {
    chrome.storage.local.get('generatedPassword', function(result) {
        if (result.generatedPassword) {
            const password = result.generatedPassword;

            // Inject the password into the active password field
            chrome.scripting.executeScript({
                target: { tabId: tabId },
                function: (password) => {
                    const passwordField = document.querySelector('input[type="password"]');
                    if (passwordField) {
                        passwordField.value = password;
                        // Trigger the change event to simulate user input
                        const event = new Event('change', { bubbles: true });
                        passwordField.dispatchEvent(event);
                    } else {
                        alert('No password field found!');
                    }
                },
                args: [password]
            });
        } else {
            alert('No generated password found in storage.');
        }
    });
}













