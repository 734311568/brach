<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">

	<xsl:output
		encoding="UTF-8"
		media-type="text/html"
		method="html"
		indent="no"
		omit-xml-declaration="yes"
	/>

	<!--文件-->
	<xsl:template match="/">
		<xsl:text disable-output-escaping="yes">&#60;!DOCTYPE HTML&#62;</xsl:text>
		<HTML lang="en">
			<xsl:apply-templates select="document"/>
			<SCRIPT src="/resources/js/init.js"></SCRIPT>
			
			<!-- Begin 社群相關功能 -->
			<SCRIPT src="/resources/js/likeAndBookSubmit.js"></SCRIPT>
			<SCRIPT src="/resources/js/postStory.js"></SCRIPT>
			<SCRIPT src="/resources/js/postComment.js"></SCRIPT>
			<SCRIPT src="/resources/js/memberCenter.js"></SCRIPT>
			<SCRIPT src="/resources/js/personalHomepage.js"></SCRIPT>
			<SCRIPT src="/resources/js/share.js"></SCRIPT>
			<SCRIPT src="/resources/js/bookmark.js"></SCRIPT>
			<!-- End 社群相關功能 -->
		</HTML>
	</xsl:template>

	<xsl:template match="document">
		<HEAD>
			<!-- Required meta tags -->
			<META charset="utf-8" />
			<META name="viewport"
			      content="width=device-width, initial-scale=1, shrink-to-fit=no" />
			<!-- Bootstrap CSS -->
			<LINK rel="stylesheet"
			      href="https://stackpath.bootstrapcdn.com/bootstrap/4.2.1/css/bootstrap.min.css"
			      integrity="sha384-GJzZqFGwb1QTTN6wy59ffF1BuGJpLSa9DkKMp0DgiMDm4iYMj70gZWKYbI706tWS" crossorigin="anonymous" />
			<LINK rel="stylesheet" href="https://use.fontawesome.com/releases/v5.5.0/css/all.css" crossorigin="anonymous" />
			<LINK href="/resources/css/fileinput.css" media="all" rel="stylesheet" type="text/css" />
			<LINK rel="stylesheet" type="text/css" href="https://bootstrap.hexschool.com/docs/4.1/examples/offcanvas/offcanvas.css" />
			<LINK rel="stylesheet" href="/resources/css/style6.css" />
			<LINK href="/resources/emoji/css/emoji.css" rel="stylesheet" />
			<LINK rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.4.0/css/font-awesome.min.css" />
			<LINK rel="stylesheet" type="text/css" href="/resources/css/redan.css" />
			
			<!--<SCRIPT src="https://code.jquery.com/jquery-3.3.1.min.js" crossorigin="anonymous"></SCRIPT>-->
			<SCRIPT src="/resources/js/jquery-3.3.1.min.js"></SCRIPT>
			<SCRIPT
				src="https://stackpath.bootstrapcdn.com/bootstrap/4.2.1/js/bootstrap.min.js"
				integrity="sha384-B0UglyR+jN6CkvvICOB2joaf5I4l3gm9GU6Hc1og6Ls7i6U/mkkaduKaBhlAXv9k"
				crossorigin="anonymous">
			</SCRIPT>
			<SCRIPT src="/resources/js/bootstrap-suggest.js"></SCRIPT>
			<SCRIPT src="/resources/js/plugins/sortable.js"></SCRIPT>
			<SCRIPT src="/resources/js/fileinput.js"></SCRIPT>
			<SCRIPT src="/resources/js/locales/fr.js"></SCRIPT>
			<SCRIPT src="/resources/js/locales/es.js"></SCRIPT>
			<SCRIPT src="/resources/themes/fas/theme.js"></SCRIPT>
			<SCRIPT src="/resources/themes/explorer-fas/theme.js"></SCRIPT>
			<SCRIPT
				src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.6/umd/popper.min.js"
				integrity="sha384-wHAiFfRlMFy6i5SRaxvfOCifBUQy1xHdJ/yoi7FRNXMRBu5WHdZYu1hA6ZOblgut"
				crossorigin="anonymous">
			</SCRIPT>
			<!-- Begin emoji-picker JavaScript -->
			<SCRIPT src="/resources/emoji/js/config.js"></SCRIPT>
			<SCRIPT src="/resources/emoji/js/util.js"></SCRIPT>
			<SCRIPT src="/resources/emoji/js/jquery.emojiarea.js"></SCRIPT>
			<SCRIPT src="/resources/emoji/js/emoji-picker.js"></SCRIPT>
			<SCRIPT src="/resources/js/aws-sdk-2.283.1.min.js"></SCRIPT>
			<SCRIPT src="/resources/js/s3init.js"></SCRIPT>
			<!-- End emoji-picker JavaScript -->
			<!--clipboard复制插件-->
			<script src="https://cdnjs.cloudflare.com/ajax/libs/clipboard.js/2.0.0/clipboard.min.js"></script>
			<TITLE>Hello, 這裡是BBMall!</TITLE>
		</HEAD>
		<BODY>
			<HEADER>
				<NAV class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
					<DIV class="d-xl-none">
						<BUTTON type="button" class="btn btn-secondary " onclick="history.back()">
							<I CLass="fas fa-chevron-left text-white"></I>
						</BUTTON>
					</DIV>
					<FORM class="form-inline">
						<INPUT class="form-control" type="text" placeholder="Search" aria-label="Search" />
					</FORM>
					<BUTTON class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarCollapse"
						aria-controls="navbarCollapse" aria-expanded="false" aria-label="Toggle navigation">
						<SPAN class="navbar-toggler-icon"></SPAN>
					</BUTTON>
					<DIV class="collapse navbar-collapse" id="navbarCollapse">
						<UL class="navbar-nav mr-auto">
							<LI class="nav-item active">
								<A CLass="nav-link" href="#">page</A>
							</LI>
							<LI class="nav-item">
								<A CLass="nav-link" href="#">page</A>
							</LI>
							<LI class="nav-item">
								<A CLass="nav-link disabled" href="#">page</A>
							</LI>
						</UL>
						<DIV>
							<xsl:if test="@me">
								<BUTTON name="memberCenter" class="btn btn-dark">會員中心</BUTTON>
							</xsl:if>
						</DIV>
						<!-- 登入 -->
						<FORM action="/login/" method="GET">			
							<xsl:if test="not(@me)">
								<BUTTON type="submit" class="btn btn-light">登入/註冊</BUTTON>
							</xsl:if>
							<xsl:if test="@nickname">
								<A href="javascript:void(0)" style="color: white;">HI! <xsl:value-of select="@nickname"/></A>
							</xsl:if>
							<BR />
							<xsl:if test="@thirdParty">
								<A href="javascript:void(0)" style="color: white;">以<xsl:value-of select="@thirdParty"/>登入</A>
							</xsl:if>
						</FORM>
						<!-- 登出 -->
						<FORM action="/logout/" method="GET">
							<xsl:if test="@me">
								<BUTTON type="submit" class="btn btn-dark">登出</BUTTON>
							</xsl:if>
						</FORM>
						
					</DIV>
				</NAV>
			</HEADER>
			<MAIN class="container">
				<DIV class="my-3 p-3 rounded">
					<DIV class="row">
						<!-- sidebar -->
						<DIV class="col-md-4 d-none d-lg-block">
							<DIV class="position-fixed childScrollBar" style="height:460px;">
								<DIV class="p-3 bg-white rounded ">
									<I CLass="fas fa-user"></I>
									<DIV class="d-inline">
										<STRONG class="text-muted">
											<SPAN class="badge badge-secondary badge-pill">3</SPAN>
										</STRONG>
									</DIV>
								</DIV>
								<NAV id="sidebar" class="p-3 bg-white rounded">
									<UL class="list-group sticky-top">
										<LI>
											<A href="#homeSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">商品分類</A>
											<UL class="collapse list-unstyled" id="homeSubmenu">
												<LI>
													<A HRef="#">養生系列</A>
												</LI>
												<LI>
													<A HRef="#">週邊商品</A>
												</LI>
												<LI>
													<A HRef="#">Home 3</A>
												</LI>
											</UL>
										</LI>
										<LI>
											<A HRef="#pageSubmenu" data-toggle="collapse" aria-expanded="false" class="dropdown-toggle">活動專區</A>
											<UL class="collapse list-unstyled" id="pageSubmenu">
												<LI>
													<A HRef="#">Page 1</A>
												</LI>
												<LI>
													<A HRef="#">Page 2</A>
												</LI>
												<LI>
													<A HRef="#">Page 3</A>
												</LI>
											</UL>
										</LI>
										<LI>
											<A HRef="#">@紅配綠</A>
										</LI>
										<LI>
											<A HRef="#">Contact</A>
										</LI>
									</UL>
								</NAV>
								<FOOTER>
									<DIV class="footer-copyright text-center py-3">
										© 2019 Copyright:
										<A HRef="https://mdbootstrap.com/education/bootstrap/"> redan.com</A>
									</DIV>
								</FOOTER>
							</DIV>
							<!-- sidebar end -->
						</DIV>
						<DIV class="col-md-8 col-sm-12">
							<DIV class="card mb-3">
								<INPUT name="whoId" type="hidden" value="{@id}"/>
								<TEXTAREA class="form-control textarea-control" rows="2" placeholder="請輸入文字...." data-emojiable="true" data-emoji-input="unicode">
								</TEXTAREA>
								<DIV class="p-1">
									<DIV class="file-loading">
										<INPUT id="input-b9" name="input-b9[]" multiple="" type="file" />
									</DIV>
									<DIV id="kartik-file-errors"></DIV>
								</DIV>

								<!-- tag friend dashboad -->
								<DIV class="modal fade" id="tagFriend" tabindex="-1" role="dialog" aria-labelledby="tagFriendLabel" aria-hidden="true">
									<DIV class="modal-dialog modal-lg" role="document">
										<DIV class="modal-content">
											<DIV class="modal-header">
												<H5 class="modal-title" id="tagFriendLabel">標註朋友</H5>
												<BUTTON type="button" class="close" data-dismiss="modal" aria-label="Close">
													<SPAN aria-hidden="true">×</SPAN>
												</BUTTON>
											</DIV>
											<DIV class="modal-body">
												<DIV class="input-group" style="width: 100%;">
													<INPUT type="text" class="form-control" id="modalTest_input" autocomplete="off" style="border-radius: 4px; background: rgb(255, 255, 255);" data-id="" alt="" />
													<DIV class="input-group-btn">
														<BUTTON type="button" class="btn btn-default dropdown-toggle" data-toggle="" style="display: none;">
															<SPAN class="caret"></SPAN>
														</BUTTON>
														<UL class="dropdown-menu dropdown-menu-right" role="menu" style=" max-height: 375px; overflow: auto; display: block;">
															<TABLE class="table table-condensed table-sm" style="margin:0">
																<THEAD>
																	<TR>
																		<TH>UserName(31)</TH>
																	</TR>
																</THEAD>
																<TBODY>
																	<TR Data-index="0" data-id="20001" data-key="淳芸">
																		<TD Data-name="userName">淳芸</TD>
																	</TR>
																	<TR Data-index="1" data-id="20000" data-key="orion-01">
																		<TD Data-name="userName">orion-01</TD>
																	</TR>
																	<TR Data-index="2" data-id="20011" data-key="唐宏禹14">
																		<TD Data-name="userName">唐宏禹14</TD>
																	</TR>
																	<TR Data-index="3" data-id="20011" data-key="唐宏禹13">
																		<TD Data-name="userName">唐宏禹13</TD>
																	</TR>
																	<TR Data-index="4" data-id="20002" data-key="穆晓晨">
																		<TD Data-name="userName">穆晓晨</TD>
																	</TR>
																	<TR Data-index="5" data-id="20003" data-key="张欢引">
																		<TD Data-name="userName">张欢引</TD>
																	</TR>
																	<TR Data-index="6" data-id="20004" data-key="吴琼">
																		<TD Data-name="userName">吴琼</TD>
																	</TR>
																	<TR Data-index="7" data-id="20005" data-key="吴东鹏">
																		<TD Data-name="userName">吴东鹏</TD>
																	</TR>
																	<TR Data-index="8" data-id="20006" data-key="黄少铅">
																		<TD Data-name="userName">黄少铅</TD>
																	</TR>
																	<TR Data-index="9" data-id="20007" data-key="胡运燕">
																		<TD Data-name="userName">胡运燕</TD>
																	</TR>
																	<TR Data-index="10" data-id="20008" data-key="刘幸">
																		<TD Data-name="userName">刘幸</TD>
																	</TR>
																	<TR Data-index="11" data-id="20009" data-key="陈媛媛">
																		<TD Data-name="userName">陈媛媛</TD>
																	</TR>
																	<TR Data-index="12" data-id="20010" data-key="李大鹏">
																		<TD Data-name="userName">李大鹏</TD>
																	</TR>
																	<TR Data-index="13" data-id="20011" data-key="唐宏禹">
																		<TD Data-name="userName">唐宏禹</TD>
																	</TR>
																	<TR Data-index="14" data-id="20010" data-key="旷东林">
																		<TD Data-name="userName">旷东林</TD>
																	</TR>
																	<TR Data-index="15" data-id="20011" data-key="唐宏禹15">
																		<TD Data-name="userName">唐宏禹15</TD>
																	</TR>
																	<TR Data-index="16" data-id="20011" data-key="唐宏禹12">
																		<TD Data-name="userName">唐宏禹12</TD>
																	</TR>
																	<TR Data-index="17" data-id="20011" data-key="唐宏禹11">
																		<TD Data-name="userName">唐宏禹11</TD>
																	</TR>
																	<TR Data-index="18" data-id="20010" data-key="旷东林">
																		<TD Data-name="userName">旷东林</TD>
																	</TR>
																	<TR Data-index="19" data-id="20011" data-key="唐宏禹10">
																		<TD Data-name="userName">唐宏禹10</TD>
																	</TR>
																	<TR Data-index="20" data-id="20011" data-key="唐宏禹">
																		<TD Data-name="userName">唐宏禹</TD>
																	</TR>
																	<TR Data-index="21" data-id="20011" data-key="唐宏禹9">
																		<TD Data-name="userName">唐宏禹9</TD>
																	</TR>
																	<TR Data-index="22" data-id="20011" data-key="唐宏禹8">
																		<TD Data-name="userName">唐宏禹8</TD>
																	</TR>
																	<TR Data-index="23" data-id="20011" data-key="唐宏禹7">
																		<TD Data-name="userName">唐宏禹7</TD>
																	</TR>
																	<TR Data-index="24" data-id="20010" data-key="旷东林">
																		<TD Data-name="userName">旷东林</TD>
																	</TR>
																	<TR Data-index="25" data-id="20011" data-key="唐宏禹6">
																		<TD Data-name="userName">唐宏禹6</TD>
																	</TR>
																	<TR Data-index="26" data-id="20011" data-key="唐宏禹5">
																		<TD Data-name="userName">唐宏禹5</TD>
																	</TR>
																	<TR Data-index="27" data-id="20011" data-key="唐宏禹4">
																		<TD Data-name="userName">唐宏禹4</TD>
																	</TR>
																	<TR Data-index="28" data-id="20011" data-key="唐宏禹3">
																		<TD Data-name="userName">唐宏禹3</TD>
																	</TR>
																	<TR Data-index="29" data-id="20011" data-key="唐宏禹2">
																		<TD Data-name="userName">唐宏禹2</TD>
																	</TR>
																	<TR Data-index="30" data-id="20011" data-key="唐宏禹1">
																		<TD Data-name="userName">唐宏禹1</TD>
																	</TR>
																</TBODY>
															</TABLE>
														</UL>
													</DIV>
													<!-- /btn-group -->
												</DIV>
											</DIV>
											<DIV class="modal-footer">
												<BUTTON type="button" class="btn btn-secondary" data-dismiss="modal">Close</BUTTON>
											</DIV>
										</DIV>
									</DIV>
								</DIV>   <!-- TAG FRIEND DASHBOAD END -->
								<!-- file upload dashboad -->
								
							</DIV>
							<!-- story -->
							<xsl:apply-templates select="stories"/>
							<!-- story end -->
						</DIV>
					</DIV>
				</DIV>
				<HR />
				<DIV class="text-center">
					載入中...
					<DIV class="spinner-grow" role="status">
						<SPAN class="sr-only"></SPAN>
					</DIV>
				</DIV>
				<HR />

				<FOOTER>
					<DIV class="footer-copyright text-center py-3 d-xl-none">
						© 2019 Copyright:
						<A HRef="https://mdbootstrap.com/education/bootstrap/"> redan.com</A>
					</DIV>
				</FOOTER>

				<FOOTER class="page-footer fixed-bottom bg-dark">
					<DIV class="row justify-content-around p-2 d-xl-none">
						<DIV class="col-2 text-white mobileFooterButton">
							<I CLass="fas fa-home"></I>
						</DIV>
						<DIV class="col-2 text-white mobileFooterButton">
							<I CLass="fas fa-shopping-bag"></I>
						</DIV>
						<DIV class="col-2 text-white mobileFooterButtonPlus">
							<I CLass="far fa-plus-square"></I>
						</DIV>
						<DIV class="col-2 text-white mobileFooterButton">
							<I CLass="fas fa-bookmark"></I>
						</DIV>
						<DIV class="col-2 text-white mobileFooterButton">
							<I CLass="fas fa-user"></I>
						</DIV>
					</DIV>
				</FOOTER>
			</MAIN>			
		</BODY>
	</xsl:template>

	<!--stories-->
	<xsl:template match="stories">
		<xsl:apply-templates select="story"/>
	</xsl:template>

	<!--story-->
	<xsl:template match="story">
		<DIV class="story_name">
			<DIV class="card mb-4">
				<!-- carousel -->
				<DIV class="carousel slide" data-ride="carousel">
					<xsl:attribute name="id">
						<xsl:value-of select="generate-id(@id)"/>
					</xsl:attribute>
					<!-- story-title -->
					<DIV class="p-2 mb-5">
						<BUTTON type="button" class="float-left btn btn-outline-light">
							<A title="theofficialai3" class="text-dark" href="/theofficialai3/">
								<!-- img ioc -->
								<img class="div-ioc" src="{author/@profileImgUrl}"/>
								<xsl:value-of select="author/@nickname"/>
							</A>
						</BUTTON>
						<DIV class="float-right">
							<A CLass="text-muted">
								<xsl:value-of select="@postedAt"/>
							</A>
						</DIV>
					</DIV>
					<OL class="carousel-indicators">
						<xsl:for-each select = "storyImages/storyImage">
							<LI data-slide-to="{@count}" class="active">
								<xsl:attribute name="Data-target">&#35;
									<xsl:value-of select="generate-id(@id)"/>
								</xsl:attribute>
								<xsl:if test="@count=0">
									<xsl:attribute name="class">active</xsl:attribute>
								</xsl:if>
							</LI>
						</xsl:for-each>
					</OL>					
					<DIV class="carousel-inner">
						<xsl:apply-templates select="storyImages"/>
					</DIV>
					<A CLass="carousel-control-prev"
					   href="/Personalpage" role="button" data-slide="prev">
						<!-- 					   	<IMG src="{author/@profilImg}" class="rounded-circle"/> -->
						<SPAN class="carousel-control-prev-icon" aria-hidden="true"></SPAN>
						<SPAN class="sr-only">Previous</SPAN>
					</A>
					<A CLass="carousel-control-next"
					   href="#carouselExampleIndicators" role="button" data-slide="next">
						<SPAN class="carousel-control-next-icon" aria-hidden="true"></SPAN>
						<SPAN class="sr-only">Next</SPAN>
					</A>
				</DIV>
			</DIV>
			<DIV class="card-body">
				<P CLass="card-text">
					<xsl:value-of select="content"/>
				</P>
				<DIV>
					<DIV class="d-flex justify-content-between align-items-center">
						<!--分享的模态框-->
						<div class="modal" id="mymodal">
							<div class="modal-dialog">
								
								<div class="modal-content">
									<div class="modal-header">
										分享
										<a  class="close"   data-dismiss="modal" aria-hidden="true"  onclick="myclike(this.value)">
										&#215; 
										</a>
									</div>
									
									<div class="modal-body">
										<I CLass="fas  fa-share-alt" />
										<input id="foo" value="http://localhost:8080/"/>
										
									</div>
									<div class="modal-footer">
										<a href="#" class="btn" data-clipboard-target="#foo" data-clipboard-action="copy"  data-dismiss="modal" >复制</a>	
									</div>
								</div>
							</div>
						</div>
						<DIV class="btn-group">
							<FORM>
								<BUTTON type="button" class="btn btn-lg btn-light"  value="copy"  onclick="myclike(this.value)">
									<I CLass="fas fa-share-alt"/>
								</BUTTON>
							</FORM>
							<FORM>
								<BUTTON data-target = "&#35;&#97;{generate-id(@id)}" type="button" class="btn btn-lg btn-light" data-toggle="collapse" aria-controls="collapseExample" aria-expanded="false">
									<I CLass="fas fa-comments"/>
								</BUTTON>
							</FORM>
							<FORM action="/like/" method="POST" class="mode">
								<INPUT name="story" type="hidden" value="{@id}"/>
								<INPUT name="who" type="hidden" value="{/document/@me}"/>
								<BUTTON type="submit" class="btn btn-lg btn-light">
									<I title="{@emotions}" CLass="far fa-heart"/>
								</BUTTON>
								<!--<I CLass="{like/emotion[selected]}"/>-->
							</FORM>
							<FORM action="/bookmark/" method="POST" class="mode">
								<INPUT name="story" type="hidden" value="{@id}"/>
								<INPUT name="who" type="hidden" value="{/document/@me}"/>
								<BUTTON type="submit" class="btn btn-lg btn-light">
									<I CLass="far fa-bookmark"></I>
								</BUTTON>
							</FORM>
						</DIV>
					</DIV>
					<DIV class="col collapse" id="&#97;{generate-id(@id)}">
						<HR/>
						<FORM action="/postComment/" method="PUT" class="mode" style="margin-bottom:-10px">
							<P CLass="lead emoji-picker-container">
								<INPUT type="hidden" name="who" value="{/document/@personnelHref}"/>
								<INPUT type="hidden" name="storyId" value="{@id}"/>
								<INPUT type="hidden" name="storyHref" value="{href}"/>
								<INPUT type="text" name="content" placeholder="留言..."/>
								<BUTTON type="submit" class="btn btn-lg btn-light">送出</BUTTON>
							</P>
						</FORM>
						<BR/>
						<BR/>
						<xsl:apply-templates select="comments"/>
					</DIV>
				</DIV>
			</DIV>
		</DIV>
	</xsl:template>
	
	<!--storyImage-->
	<xsl:template match="storyImages">
		<xsl:apply-templates select="storyImage"/>
	</xsl:template>
	
	<!--url-->
	<xsl:template match="storyImage">
		<DIV class="{@mode}">
			<IMG class="d-block w-100" alt="First slide">
				<xsl:attribute name="src">
					<xsl:value-of select="url"/>
				</xsl:attribute>
			</IMG>
			<!--src="https://www.orangelady99.com/tw/upload_files/fonlego-rwd/prodpic/D_%E8%8F%93%E7%84%B6%E5%B9%B8%E7%A6%8F-%E5%A4%9A%E9%81%94%E5%8D%81%E5%B9%BE%E7%A8%AE%E7%86%B1%E8%B3%A3%E5%A4%A9%E7%84%B6%E6%B0%B4%E6%9E%9C%E4%B9%BE.jpg"--> 
		</DIV>
	</xsl:template>
	
	<!--comments-->
	<xsl:template match="comments">
		<DIV class="col" id="{../@id}">
			<!--a<xsl:value-of select="id"/>
			<xsl:attribute name="id">&#97;
				<xsl:value-of select="generate-id(../@id)"/>
			</xsl:attribute>-->
			<xsl:apply-templates select="comment"/>
		</DIV>
		<BUTTON class="topic-more-comm">載入更多留言</BUTTON>
	</xsl:template>
	
	<!--comment-->
	<xsl:template match="comment">
		<UL class="topic-comm" style="clear:both">
			<LI>
				<DIV class="d-inline">
					<!--这里植入评论者头像-->
					<A class="text-left text-dark ioc"  whoid="{who/@id}"  title="{who/@nickname}"  href="/Personalpage?id={who/@id}">
						<img  class="ioc"  imgvalueid="{who/@id}"   src="" />
						<xsl:value-of select="who/@nickname"/>
					</A>
				</DIV>
				<SPAN class="d-inline">
					<xsl:value-of select="content"/>
					<!--<A HRef="/shareefoneal/">@shareefoneal</A>-->
				</SPAN>
			</LI>
		</UL>
	</xsl:template>
</xsl:stylesheet>