/**
 * 在模态框使用复制插件复制链接
 * 
 * 
 */
function myclike(value) {
	
	//初始化模态框
	$("#mymodal").modal({
		//点击背景不关闭
		backdrop: "static",
		//触发键盘esc事件时不关闭
		keyboard: false
	});
	//$('#mymodel').modal('show');
	//设置模态框隐藏事件
	if (value === "copy") {
		$('#mymodal a.btn').click(function () {
			var textValue = $("input#foo").val();
			new ClipboardJS('.btn', {
				text: function () {
					return textValue;
				}});
		});
	} else {
		$('#mymodal a.close').click(function () {
			$(this).unbind();

		});


	}





}
