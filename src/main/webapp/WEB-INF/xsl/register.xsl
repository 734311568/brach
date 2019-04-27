<?xml version='1.0' encoding='UTF-8' ?>
<!-- was: <?xml version="1.0"?> -->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<xsl:output
		encoding="UTF-8"
		media-type="text/HTML"		
		indent="no"
		omit-xml-declaration="yes"/>

	<!-- TODO customize transformation rules 
	     syntax recommendation http://www.w3.org/TR/xslt 
	-->
	<xsl:template match="/">
		<HTML lang="en">
			<HEAD>
				<META charset="utf-8"/>
				<META http-equiv="X-UA-Compatible" content="IE=edge"/>
				<META name="viewport" content="width=device-width, initial-scale=1"/>
				<LINK href="https://fonts.googleapis.com/css?family=Roboto:400,700" rel="stylesheet"/>
				<TITLE>會員註冊</TITLE>
				<LINK rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"/>
				<LINK rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css"/>
				<SCRIPT src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></SCRIPT>
				<SCRIPT src="/resources/js/jquery-3.3.1.min.js"></SCRIPT>
				<SCRIPT src="/resources/js/register.js"></SCRIPT>
				<STYLE type="text/css">
					BODY{
					color: #fff;
					background: #63738a;
					font-family: 'Roboto', sans-serif;
					}
					.form-control{
					height: 40px;
					box-shadow: none;
					color: #969fa4;
					}
					.form-control:focus{
					border-color: #5cb85c;
					}
					.form-control, .btn{        
					border-radius: 3px;
					}
					.signup-form{
					width: 400px;
					margin: 0 auto;
					padding: 30px 0;
					}
					.signup-form h2{
					color: #636363;
					margin: 0 0 15px;
					position: relative;
					text-align: center;
					}
					.signup-form h2:before, .signup-form h2:after{
					content: "";
					height: 2px;
					width: 30%;
					background: #d4d4d4;
					position: absolute;
					top: 50%;
					z-index: 2;
					}   
					.signup-form h2:before{
					left: 0;
					}
					.signup-form h2:after{
					right: 0;
					}
					.signup-form .hint-text{
					color: #999;
					margin-bottom: 30px;
					text-align: center;
					}
					.signup-form form{
					color: #999;
					border-radius: 3px;
					margin-bottom: 15px;
					background: #f2f3f7;
					box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);
					padding: 30px;
					}
					.signup-form .form-group{
					margin-bottom: 20px;
					}
					.signup-form input[type="checkbox"]{
					margin-top: 3px;
					}
					.signup-form .btn{        
					font-size: 16px;
					font-weight: bold;      
					min-width: 140px;
					outline: none !important;
					}
					.signup-form .row DIV:first-child{
					padding-right: 10px;
					}
					.signup-form .row DIV:last-child{
					padding-left: 10px;
					}       
					.signup-form a{
					color: #fff;
					text-decoration: underline;
					}
					.signup-form a:hover{
					text-decoration: none;
					}
					.signup-form form a{
					color: #5cb85c;
					text-decoration: none;
					}   
					.signup-form form a:hover{
					text-decoration: underline;
					}  
				</STYLE>
			</HEAD>
			<BODY>
				<DIV class="signup-form">
					<FORM action="/register/" method="POST" enctype="multipart/form-data" accept-charset="UTF-8">
						<H2>會員註冊</H2>
						<P class="hint-text">填寫以下資訊，這只需要一點點時間</P>
						<DIV class="form-group">
							<DIV class="row">
								<DIV class="col-xs-6">
									<INPUT type="text" class="form-control" name="lastName" placeholder="姓氏" required=""/>
								</DIV>
								<DIV class="col-xs-6">
									<INPUT type="text" class="form-control" name="firstName" placeholder="名字" required=""/>
								</DIV>
							</DIV>          
						</DIV>
						<DIV class="form-group">
							<INPUT type="email" class="form-control" name="email" placeholder="Email" required=""/>
						</DIV>
						<DIV class="form-group">
							<INPUT type="password" class="form-control" name="password" placeholder="密碼" required="" aria-autocomplete="list"/>
						</DIV>
						<DIV class="form-group">
							<INPUT type="password" class="form-control" name="confirmPassword" placeholder="請再輸入一次密碼" required=""/>
						</DIV>        
						<DIV class="form-group">
							<LABEL class="checkbox-inline">
								<INPUT type="checkbox" required=""> 我同意此網站的 <A href="#">資料使用政策</A> &amp; 
									<A href="#">隱私條款</A>
								</INPUT>
							</LABEL>
						</DIV>
						<DIV class="form-group">
							<BUTTON type="submit" class="btn btn-success btn-lg btn-block">註冊</BUTTON>
						</DIV>
					</FORM>
					<DIV class="text-center">已經有帳號了？ <A href="/login">馬上登入</A></DIV>
				</DIV>

			</BODY>
		</HTML>
	</xsl:template>

</xsl:stylesheet>
