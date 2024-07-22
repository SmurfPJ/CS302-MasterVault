chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PASSWORD_INPUT_FOCUSED") {
    const notificationId = `password-focused-${Date.now()}`;

    chrome.notifications.create(notificationId, {
      type: 'basic',
      iconUrl: 'images/Logo16x16.png',
      title: 'MasterVault',
      message: 'A reminder to secure your passwords using our password generator!',
      priority: 2
    });
  }
});










