$(document).ready(function () {
	//member center
	$('BUTTON[name="memberCenter"]').on('click', function () {
		window.location.href = '/memberCenter';
	});
});

//添加好友
function clearModal(id) {
	$.post("addFriend", {"id": id}, function (data) {

		if ("You don't have required role to perform this action." === data) {
			alert("请先登入");
			window.location.href = "/login";
		} else {
			alert(data);
			location.reload();
		}

	});
}


//调整页面
//function getMemberCenterId(id) {
//	//获取输入的分行数据
//	var s = $("#select option:selected").val();
//
//	$.post("memberCenterJson", {"id": id}, function (data) {
//		//清除之前展示数据
//		$("#divs").empty();
//		//获取数据
//		var json = JSON.parse(data);
//		var userStoryArray = json["userStory"];
//		var div = null;
//		for (var i = 0; i < userStoryArray.length; i++) {
//			var storyImage = userStoryArray[i]["storyImage"];
//			//设置每行几列图片
//			if (i == 0 || i % s == 0) {
//				var thatsokDiv = document.createElement("div");
//				$(div).attr({"class": "row mt-1"});
//				$("#divs").append(thatsokDiv);
//			}
//			//设置占位
//			var columnDiv = document.createElement("div");
//			$(columnDiv).attr({"class": "col-sm-4"});
//			$(thatsokDiv).append(columnDiv);
//			var columnDiv2 = document.createElement("div");
//			$(columnDiv2).attr({"class": "thumbnail"});
//			$(columnDiv).append(columnDiv2);
//			//超链接与图片
//			var a = document.createElement("a");
//			$(a).attr({"class": "", "href": "#"});
//			$(columnDiv2).append(a);
//			var img = document.createElement("img");
//			//判断如果每一行只有一图不加样式
//			if (s == 1) {
//				$(img).attr({"class": "", "alt": "...", "src": storyImage["imgUrl"]});
//			} else {
//				$(img).attr({"class": "image-imUrl", "alt": "...", "src": storyImage["imgUrl"]});
//			}
//			$(a).append(img);
//		}
//	});
//}


