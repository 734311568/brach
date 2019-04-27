$(document).ready(function () {
	//post comment
	$('FORM[method="PUT"]').submit(function (e) {
		e.preventDefault();
		var storyId = $(this).children().children('INPUT[name="storyId"]').val();
		$.post($(this).attr('action'), $(this).serialize(), function (data) {
			if (data === null || data === "You don't have required role to perform this action.")
			{
				alert("請登入帳號以繼續...");
				window.location.href = "/login";
				return false;
			}
//			document.getElementById(storyId).innerHTML = data;
			$('INPUT[name="content"]').val('');

			// style=\"background: gray;opacity: 0.5;\"
//			$("div").fadeIn(3000, function () {
//				$("div").fadeOut(3000);
//			});
			var mydivElement = document.getElementById(storyId);
			mydivElement.innerHTML = '';
			//alert(data);
			//[{who: 'pc', content: '這是一則留言'}, {who: 'chiah', content: '這是第二則留言'}];

			$.each($.parseJSON(data), function (idx, obj) {
				var ulElement = document.createElement('UL'), liElement = document.createElement('LI'), divElement = document.createElement('DIV'),
					aElement = document.createElement('A'), spanElement = document.createElement('SPAN');
				$(liElement).append($(divElement).attr({'class': 'd-inline'}).append($(aElement).attr({
					'class': 'text-left text-dark',
					'title': obj.who,
					'href': obj.who
				}).text(obj.who + ' ')));
				$(liElement).append($(spanElement).attr({'class': 'd-inline'}).text(obj.content));

				$(mydivElement).append($(ulElement).attr({
					'class': 'topic-comm',
					'style': 'clear:both'
				}).append($(liElement)));
			});
		}, 'text');
	});
});