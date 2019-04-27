<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
   
    <xsl:template match="/" mode="header">
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
								<a href="/memberCenter">
									<BUTTON name="memberCenter" class="btn btn-dark" href="/memberCenter">會員中心</BUTTON>
								</a>
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
			
    </xsl:template>

</xsl:stylesheet>