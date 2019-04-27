$(document).ready(function () {
	//post story
	$("#post-story-button").click(function () {
		var storyContent = $('TEXTAREA').val();
		var user = $('INPUT[name="whoId"]').val();
//		var myImgUrls = [];
		console.log('imgUrls:');
		console.log(imgUrls);


		var myImgUrls = {
			urls: []
		};
		if (typeof imgUrls !== 'undefined') {
			for (var i = 0; i < imgUrls.length; i++) {
				var item = imgUrls[i];
				myImgUrls.urls.push({"url": item});
			}
		}

		var jsonString = JSON.stringify(myImgUrls);

		var storydata = {
			storyHref: $('INPUT[name="storyHref"]').val(),
			storyContent: storyContent,
			who: user,
			imgUrls: jsonString};

		$.post('/postStory', storydata, function (data) {
			if (data === null || data === "You don't have required role to perform this action.")
			{
				alert("請登入帳號以繼續...");
				window.location.href = "/login";
				return false;
			}
			console.log(data);
			window.location.href = '/';
		}, 'text');
	});
});