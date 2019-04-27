var albumBucketName = 'tmp-img';
AWS.config.region = 'ap-southeast-1'; // 區域
AWS.config.credentials = new AWS.CognitoIdentityCredentials({
	IdentityPoolId: 'ap-southeast-1:565217a1-1221-4493-bc15-e7095837e7b0',
});

var s3 = new AWS.S3({
	apiVersion: '2006-03-01',
	params: {Bucket: 'tmp-img'}
});

function listAlbums() {

	s3.listObjects({Delimiter: '/'}, function (err, data) {
		if (err) {
			return alert('There was an error listing your albums: ' + err.message);
		} else {
			var albums = data.CommonPrefixes.map(function (commonPrefix) {
				var prefix = commonPrefix.Prefix;
				var albumName = decodeURIComponent(prefix.replace('/', ''));
				console.log(albumName);
			});

		}
	});
}

function createAlbum(albumName) {
	albumName = albumName.trim();
	if (!albumName) {
		return alert('Album names must contain at least one non-space character.');
	}
	if (albumName.indexOf('/') !== -1) {
		return alert('Album names cannot contain slashes.');
	}
	var albumKey = encodeURIComponent(albumName) + '/';
	s3.headObject({Key: albumKey}, function (err, data) {
		if (!err) {
			return alert('Album already exists.');
		}
		if (err.code !== 'NotFound') {
			return alert('There was an error creating your album: ' + err.message);
		}
		s3.putObject({Key: albumKey}, function (err, data) {
			if (err) {
				return alert('There was an error creating your album: ' + err.message);
			}
			alert('Successfully created album.');
			viewAlbum(albumName);
		});
	});
}

function viewAlbum(albumName) {
	var albumPhotosKey = encodeURIComponent(albumName) + '//';
	s3.listObjects({Prefix: albumPhotosKey}, function (err, data) {
		if (err) {
			return alert('There was an error viewing your album: ' + err.message);
		}
		// 'this' references the AWS.Response instance that represents the response
		var href = this.request.httpRequest.endpoint.href;
		var bucketUrl = href + albumBucketName + '/';

		var photos = data.Contents.map(function (photo) {
			var photoKey = photo.Key;
			var photoUrl = bucketUrl + encodeURIComponent(photoKey);
		});
		console.log(photos);
	});
}

var result = [];
function addPhoto(albumName) {
	var files = document.getElementById('input-b9').files;
	if (!files.length) {
		return alert('Please choose a file to upload first.');
	}



	for (var i = 0; i < files.length; i++) {
		//檔案上傳中, 不可按送出
		$("#post-story-button").attr('disabled', '');

		var file = files[i];
		var fileName = file.name;
		var albumPhotosKey = encodeURIComponent(albumName) + '//';
		var photoKey = albumPhotosKey + fileName;

		s3.upload({
			Key: photoKey,
			Body: file,
			ACL: 'public-read'
		}, function (err, data) {
			if (err) {
				return alert('There was an error uploading your photo: ', err.message);
			}
			result.push(data.Location);
//			alert(data.Location);
			alert('Successfully uploaded photo.');
			console.log(data.Location);

			//檔案上傳完成, 打開送出按鈕
			$("#post-story-button").removeAttr('disabled');
		});
	}
	return result;
}

function deletePhoto(albumName, photoKey) {
	s3.deleteObject({Key: photoKey}, function (err, data) {
		if (err) {
			return alert('There was an error deleting your photo: ', err.message);
		}
		alert('Successfully deleted photo.');
		viewAlbum(albumName);
	});
}

function deleteAlbum(albumName) {
	var albumKey = encodeURIComponent(albumName) + '/';
	s3.listObjects({Prefix: albumKey}, function (err, data) {
		if (err) {
			return alert('There was an error deleting your album: ', err.message);
		}
		var objects = data.Contents.map(function (object) {
			return {Key: object.Key};
		});
		s3.deleteObjects({
			Delete: {Objects: objects, Quiet: true}
		}, function (err, data) {
			if (err) {
				return alert('There was an error deleting your album: ', err.message);
			}
			alert('Successfully deleted album.');
		});
	});
}
