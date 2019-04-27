$(document).ready(function () {
	$('FORM[method="POST"]').submit(function (e) {
		e.preventDefault();
		if ($('INPUT[name="password"]').val() !== $('INPUT[name="confirmPassword"]').val())
		{
			alert('二次密碼不相同，請重新輸入');
			return false;
		}

		$.post($(this).attr('action'), $(this).serialize(), function (data) {
			alert(data + '，正在登入...');
			$.post('/find', {thirdParty: 'BBMall', userId: '', userEmail: $('INPUT[name="email"]').val()}, function (data) {
				alert(data + '，歡迎加入BBMall！');
//				window.location.href = "/redirect?thirdParty=facebook&userName=" + data;
				window.location.href = '/';
			}, 'text');
		}, 'text');
	});
});

