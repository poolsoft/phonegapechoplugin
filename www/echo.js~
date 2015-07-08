var echo = {
    sendMessage: function(message, successCallback, errorCallback) {
		cordova.exec(successCallback, errorCallback, 'Echo', 'echo', [message]);
	}
};

module.exports = echo;