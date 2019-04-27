$(document).ready(function () {
	$('.login').on('click', function () {
		window.location.href = '/oauth2/authorize-client/' + $(this).attr('name');
	});
});