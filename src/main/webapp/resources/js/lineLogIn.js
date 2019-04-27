$(document).ready(function () {
	$('A[name="line"]').on('click', function () {
		$.post('/line', function (data) {
			window.location.href = data;
		});
	});
});