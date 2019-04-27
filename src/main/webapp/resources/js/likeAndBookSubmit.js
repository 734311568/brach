$(document).ready(function () {
	$('FORM[method="POST"]').submit(function (e) {
		e.preventDefault();
		var elementForm = $(this);
		var like = "fas", dislike = "far";
		var elementI = elementForm.children($('BUTTON')).children($('I'));

		$.post(elementForm.attr('action'), elementForm.serialize(), function (data) {
			console.log("return: " + data);
			if (data === null || data === "You don't have required role to perform this action.")
			{
				alert("請登入帳號以繼續...");
				window.location.href = "/login";
				return false;
			}
			if (elementI.hasClass(like)) {
				elementI.removeClass(like);
				elementI.addClass(dislike);
			} else {
				elementI.removeClass(dislike);
				elementI.addClass(like);
			}
		});
		return false;
	});
});