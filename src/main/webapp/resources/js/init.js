var imgUrls;

$(document).ready(function () {
	$('#input-b9').fileinput({
		theme: 'fas',
		language: 'en',
		uploadUrl: 'uploadMultipleFile',
		showRemove: false,
		showCaption: false,
		showUpload: false,
		dropZoneEnabled: false,
		browseLabel: "相片",
		allowedFileExtensions: ['jpg', 'png', 'gif']
	}).on("filebatchselected", function (event, files) {
		$('#input-b9').fileinput("upload");
		imgUrls = addPhoto('Redan');
	});
});
