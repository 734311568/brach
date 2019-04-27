package com.aws.codestar.projecttemplates.configuration.securityComponent;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.aws.codestar.projecttemplates.model.BBMuser;

/*
when login success 
	1.save user info to session 
	2.redirect to prior_url
 */
@Component("BBMSuccessHandler")
public class BBMSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		BBMuser user = (BBMuser) authentication.getPrincipal();

		HttpSession session = request.getSession();
		session.setAttribute("me", user.getUuid());
		session.setAttribute("id", user.getPersonnelId());
		session.setAttribute("personnelHref", user.getPersonnelHref());
		session.setAttribute("thirdParty", user.getThirdParty());
		session.setAttribute("nickname", user.getNickname());
		session.setAttribute("email", user.getEmail());

		if (session != null) {
			String redirectUrl = (String) session.getAttribute("url_prior_login");
			if (redirectUrl != null) {
				session.removeAttribute("url_prior_login");
				getRedirectStrategy().sendRedirect(request, response, redirectUrl);
			} else {
				super.onAuthenticationSuccess(request, response, authentication);
			}
		}
	}
}
