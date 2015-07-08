var echo = {
    getCertificateList: function(successCallback, errorCallback) {
		cordova.exec(successCallback, errorCallback, 'Echo', 'getCertificateList', []);
	},
	
	sign: function(certIndex, password, filepath, successCallback, errorCallback) {
		cordova.exec(successCallback, errorCallback, 'Echo', 'sign', [certIndex, password, filepath]);
	}
};

module.exports = echo;
