<?xml version='1.0' encoding='UTF-8' ?>
<!-- was: <?xml version="1.0"?> -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<xsl:output
		encoding="UTF-8"
		media-type="text/html"
		method="html"
		indent="no"
		omit-xml-declaration="yes"
	/>

	<!-- TODO customize transformation rules 
	     syntax recommendation http://www.w3.org/TR/xslt 
	-->
	<xsl:template match="/">
		<HTML>
			<HEAD>
				<META charset="utf-8"/>
				<META http-equiv="X-UA-Compatible" content="IE=edge"/>
				<META name="viewport" content="width=device-width, initial-scale=1"/>
				<TITLE>QQ登入</TITLE>
				<LINK rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"/>
				<LINK rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.2/css/all.css"/>
				<SCRIPT src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></SCRIPT>
				<SCRIPT src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></SCRIPT>
				<!-- Facebook Login -->
				<SCRIPT src="/resources/js/fbLogIn.js"></SCRIPT>
				<!-- Google Sign-In-->
				<META name="google-signin-scope" content="profile email"/>
				<META name="google-signin-client_id" content="386872756196-ct0oldlv5utvq3oi0lulegsgubrkjkn8.apps.googleusercontent.com"/>
				<SCRIPT src="https://apis.google.com/js/platform.js?onload=init"></SCRIPT>
				<SCRIPT src="/resources/js/googleSignIn.js"></SCRIPT>
				<!-- Line Login -->
				<SCRIPT src="/resources/js/lineLogIn.js"></SCRIPT>
				<!-- BBMall Login -->
				<SCRIPT src="/resources/js/originLogIn.js"></SCRIPT>
				<SCRIPT src="/resources/js/qq.js"></SCRIPT>
				<STYLE type="text/css">
					.login-form {
					width: 340px;
					margin: 30px auto;
					}

					.login-form form {
					margin-bottom: 15px;
					background: #f7f7f7;
					box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);
					padding: 30px;
					}

					.login-form h2 {
					margin: 0 0 15px;
					}

					.login-form .hint-text {
					color: #777;
					padding-bottom: 15px;
					text-align: center;
					}

					.form-control,
					.btn {
					min-height: 38px;
					border-radius: 2px;
					}

					.login-btn {
					font-size: 15px;
					font-weight: bold;
					}

					.or-seperator {
					margin: 20px 0 10px;
					text-align: center;
					border-top: 1px solid #ccc;
					}

					.or-seperator i {
					padding: 0 10px;
					background: #f7f7f7;
					position: relative;
					top: -11px;
					z-index: 1;
					}

					.social-btn .btn {
					margin: 10px 0;
					font-size: 15px;
					text-align: center;
					line-height: 24px;
					}

					.social-btn .btn i {
					float: left;
					margin: 4px 15px 0 5px;
					min-width: 15px;
					}

					.input-group-addon .fa {
					font-size: 18px;
					}
					
					.fab {
					font-size:20px;
					text-align: center;
					}
				</STYLE>
			</HEAD>
			<BODY>
				<DIV class="login-form">
					<FORM action="/qq/login" method="POST">
						<DIV class="text-center social-btn">
							<H2 class="text-center">QQ登入</H2>
							<DIV class="form-group">
								<DIV class="input-group">
									<SPAN class="input-group-addon">
										<I class="fa fa-user"></I>
									</SPAN>
									<INPUT type="text" class="form-control" name="userEmail" placeholder="帳號" required=""/>
								</DIV>
							</DIV>
							<DIV class="form-group">
								<DIV class="input-group">
									<SPAN class="input-group-addon">
										<I class="fa fa-lock"></I>
									</SPAN>
									<INPUT type="password" class="form-control" name="password" placeholder="密碼" required=""/>
								</DIV>
							</DIV>
							<DIV class="form-group">
								<BUTTON type="submit" class="btn btn-light btn-block login-btn">登入</BUTTON>
							</DIV>
							<DIV class="clearfix">
								<LABEL class="pull-left checkbox-inline">
									<INPUT type="checkbox"/> 記得我</LABEL>
								<A href="#" class="pull-right text-success">忘記密碼？</A>
							</DIV>
						</DIV>
					</FORM>
				</DIV>
			</BODY>
		</HTML>
	</xsl:template>
</xsl:stylesheet>
