// Load the SDK asynchronously
(function (d, s, id) {
	var js, fjs = d.getElementsByTagName(s)[0];
	if (d.getElementById(id))
		return;
	js = d.createElement(s);
	js.id = id;
	js.src = "https://connect.facebook.net/zh_TW/sdk.js";	//"zh_TW" 須留意地區切換
	fjs.parentNode.insertBefore(js, fjs);
}(document, 'script', 'facebook-jssdk'));

window.fbAsyncInit = function () {
	FB.init({
		appId: '324639151729654', //應改為系統變數
		cookie: true, // enable cookies to allow the server to access 
		// the session
		xfbml: true, // parse social plugins on this page
		version: 'v3.2' // The Graph API version to use for the call
	});

//	FB.getLoginStatus(function (response) {
//		statusChangeCallback(response);
//	});
};

$(document).ready(function () {
	$('A[name="facebook"]').on('click', function () {
		FB.login(function (response) {
			//debug用
			console.log(response);
			if (response.status === 'connected') {
				//user已登入FB
				//抓userID
				let FB_ID = response["authResponse"]["userID"];
				console.log("userID:" + FB_ID);
				console.log("Facebook response" + JSON.stringify(response));
				for (var i = 0; i < response["authResponse"].length; i++) {
					console.log("authResponse: " + response["authResponse"][i]);
				}

				FB.api('/me', {fields: 'id,first_name,middle_name,last_name,short_name,name_format,picture,email'}, function (response) {
					console.log("id: " + response.id);
					console.log("first_name: " + response.first_name);
					console.log("middle_name: " + response.middle_name);
					console.log("last_name: " + response.last_name);
					console.log("short_name: " + response.short_name);
					console.log("name_format: " + response.name_format);
					console.log("picture: " + JSON.stringify(response.picture));
					console.log("email: " + response.email);

					$.post('/find', {thirdParty: 'facebook', userId: response.id}, function (data) {
						alert(data + '，歡迎回來！');
//						window.location.href = "/redirect?thirdParty=facebook&userName=" + data;
						window.location.href = '/';
					}, 'text');
				});
			} else {
				// user FB取消授權
				alert('Facebook帳號無法登入');
			}
		}, {scope: 'public_profile,email'});

	}
	);
});