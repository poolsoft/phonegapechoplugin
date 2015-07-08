var echo = {
    getCertificateList: function(successCallback, errorCallback) {
		cordova.exec(successCallback, errorCallback, 'Echo', 'getCertificateList', []);
	},
	
	sign: function(String certIndex, String password, String filepath, successCallback, errorCallback) {
		cordova.exec(successCallback, errorCallback, 'Echo', 'sign', [certIndex, password, filepath]);
	}
};

module.exports = echo;
