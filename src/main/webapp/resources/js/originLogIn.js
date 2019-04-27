$(document).ready(function () {
	$('FORM[method="POST"]').submit(function (e) {
		e.preventDefault();
		$.post('/find', {thirdParty: 'BBMall', userId: '', userEmail: $('INPUT[name="userEmail"]').val()}, function (data) {
			alert(data + '，歡迎回來！');
//				window.location.href = "/redirect?thirdParty=facebook&userName=" + data;
			window.location.href = '/';
		}, 'text');
	});
});