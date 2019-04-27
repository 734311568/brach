/*
 * 加载对应用户的头像
 * 
 */
$(document).ready(function () {
	var btns = new Array();
	var img = new Array();
	$("a.ioc").each(function (i) {
		btns[i] = $(this).attr("whoid");
		
		$.get("/img", {"id": btns[i]}, function (data) {
			$('img.ioc').each(function (j) {
				img[j] = $(this).attr("imgvalueid");
				
				if (btns[i] === img[j]) {
					$(this).attr("src", data);
				}
			});

		}, 'text');
	});

});




