<xsl:stylesheet version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

	<xsl:template match="/" mode="header">
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
							<A href="#homeSubmenu" data-toggle="collapse"
								aria-expanded="false" class="dropdown-toggle">商品分類</A>
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
							<A HRef="#pageSubmenu" data-toggle="collapse"
								aria-expanded="false" class="dropdown-toggle">活動專區</A>
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

			</DIV>
			<!-- sidebar end -->
		</DIV>

	</xsl:template>

</xsl:stylesheet>