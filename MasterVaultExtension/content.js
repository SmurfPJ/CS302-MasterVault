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








