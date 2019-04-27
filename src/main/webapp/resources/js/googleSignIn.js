$(document).ready(function () {
	gapi.load('auth2', function () {
		// Retrieve the singleton for the GoogleAuth library and set up the client.
		auth2 = gapi.auth2.init({
			client_id: '386872756196-ct0oldlv5utvq3oi0lulegsgubrkjkn8.apps.googleusercontent.com',
			cookiepolicy: 'single_host_origin',
			// Request scopes in addition to 'profile' and 'email'
			scope: 'profile email'
		});
		attachSignin(document.getElementById('google'));
	});

	function attachSignin(element) {
//		console.log(element.id);
		auth2.attachClickHandler(element, {},
			function (googleUser) {
				var profile = googleUser.getBasicProfile();
//				alert(profile.getName());
				console.log("ID: " + profile.getId()); // Don't send this directly to your server!
				console.log('Full Name: ' + profile.getName());
				console.log('Given Name: ' + profile.getGivenName());
				console.log('Family Name: ' + profile.getFamilyName());
				console.log('Image URL: ' + profile.getImageUrl());
				console.log('Email: ' + profile.getEmail());
				console.log('Profile: ' + JSON.stringify(profile));

				$.post('/find', {thirdParty: 'google', userId: profile.getId()}, function (data) {
					alert(data + '，歡迎回來！');
//					window.location.href = "/redirect?thirdParty=google&userName=" + data;
					window.location.href = '/';
				}, 'text');
			}, function (error) {
			alert(JSON.stringify(error, undefined, 2));
		});
	}
});


