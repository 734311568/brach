package com.aws.codestar.projecttemplates.configuration.oauth2Component.user;

import java.util.Map;

import com.aws.codestar.projecttemplates.configuration.oauth2Component.AuthProvider;
import com.aws.codestar.projecttemplates.exception.OAuth2AuthenticationProcessingException;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
//            return new GoogleOAuth2UserInfo(attributes);
            return null;
        } else if (registrationId.equalsIgnoreCase(AuthProvider.facebook.toString())) {
            return new FacebookOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(AuthProvider.github.toString())) {
            return new GithubOAuth2UserInfo(attributes);
        }  else if (registrationId.equalsIgnoreCase("line")) {
            return new LineOAuth2UserInfo(attributes);
        }else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
