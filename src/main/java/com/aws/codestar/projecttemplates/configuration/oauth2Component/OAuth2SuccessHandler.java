package com.aws.codestar.projecttemplates.configuration.oauth2Component;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.aws.codestar.projecttemplates.configuration.oauth2Component.user.GoogleOAuth2UserInfo;
import com.aws.codestar.projecttemplates.model.User;


@Component("OAuth2SuccessHandler")
public class OAuth2SuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		System.out.println("onAuthenticationSuccess");
		GoogleOAuth2UserInfo googleOAuth2UserInfo;
		
		HttpSession session = request.getSession();
		
		if(authentication.getPrincipal() instanceof GoogleOAuth2UserInfo){
			
			googleOAuth2UserInfo = (GoogleOAuth2UserInfo) authentication.getPrincipal();			
			System.out.println(googleOAuth2UserInfo);
			
			session.setAttribute("me", googleOAuth2UserInfo.getUuid());
			session.setAttribute("id", googleOAuth2UserInfo.getPersonnelId());
			session.setAttribute("personnelHref", googleOAuth2UserInfo.getPersonnelHref());
			session.setAttribute("thirdParty", "google");
			session.setAttribute("nickname", googleOAuth2UserInfo.getName());
			session.setAttribute("email", googleOAuth2UserInfo.getEmail());
			
		}else if(authentication.getPrincipal() instanceof UserPrincipal){
			
			UserPrincipal facebookOauth2UserInfo = (UserPrincipal) authentication.getPrincipal();			
			Map userAttributes = facebookOauth2UserInfo.getAttributes();
			User user = facebookOauth2UserInfo.getBBMuser();		
			session.setAttribute("me", user.getUuid());
			session.setAttribute("id", user.getPersonnelId());
			session.setAttribute("personnelHref", user.getPersonnelHref());
			session.setAttribute("thirdParty", user.getThirdParty());
			session.setAttribute("nickname", user.getName());
			session.setAttribute("email", user.getEmail());
			
		}else {
			System.out.println("clients error :"+authentication.getPrincipal());			
			
		}
		
		
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
