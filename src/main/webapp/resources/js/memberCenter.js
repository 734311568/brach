$(document).ready(function () {
	//member center
	$('BUTTON[name="memberCenter"]').on('click', function () {
		window.location.href = '/memberCenter';
	});
});


function getId(id) {
	var s = $("#select option:selected").val();
	$.post("getPersonalJson", {"id": id}, function (data) {
		$("#divs").empty();
		var json = JSON.parse(data);
		var array = json["userStory"];
		var div = null;
		for (var i = 0; i < array.length; i++) {
			var storyImage = array[i]["storyImage"];
			if (i == 0 || i % s == 0) {
				div = document.createElement("div");
				$(div).attr({"class": "row mt-1"});
				$("#divs").append(div);
			}
			var div2 = document.createElement("div");
			$(div2).attr({"class": "col-sm-4"});
			$(div).append(div2);
			var div3 = document.createElement("div");
			$(div3).attr({"class": "thumbnail"});
			$(div2).append(div3);
			var a = document.createElement("a");
			$(a).attr({"class": "", "href": "#"});
			$(div3).append(a);
			var img = document.createElement("img");
			if (s == 1) {
				$(img).attr({"class": "", "alt": "...", "src": storyImage["imgUrl"]});
			} else {
				$(img).attr({"class": "image-imUrl", "alt": "...", "src": storyImage["imgUrl"]});
			}

			$(a).append(img);
		}
	});
}


