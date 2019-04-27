package com.aws.codestar.projecttemplates.configuration.oauth2Component;

import java.io.IOException;
import java.net.URISyntaxException;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.aws.codestar.projecttemplates.configuration.oauth2Component.user.OAuth2UserInfoFactory;
import com.aws.codestar.projecttemplates.exception.OAuth2AuthenticationProcessingException;
import com.aws.codestar.projecttemplates.model.User;
import com.aws.codestar.projecttemplates.service.ApiService;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

        @Autowired
        private ApiService apiService;

        @Override
        public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
                OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

                try {
                        return processOAuth2User(oAuth2UserRequest, oAuth2User);
                } catch (AuthenticationException ex) {
                        throw ex;
                } catch (Exception ex) {
                        // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
                        throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
                }
        }

        private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {

        	System.out.println("processOAuth2User");
        	System.out.println(oAuth2UserRequest.getClientRegistration().getRegistrationId());
        	System.out.println(oAuth2User.getAttributes());
                com.aws.codestar.projecttemplates.configuration.oauth2Component.user.OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
//                if (StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
//                        throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
//                }
                String clientName = null;
                JSONObject userOptional = null;
                User user = new User();
                try {

                        clientName = oAuth2UserRequest.getClientRegistration().getClientName();
                        System.out.println("oAuth2UserRequest");
                        if ("Facebook".equalsIgnoreCase(clientName)) {
                                userOptional = apiService.findOneByThirdPartyId("facebook", oAuth2UserInfo.getId());
                                System.out.println("login with facebook");
                        } else if ("Google".equalsIgnoreCase(clientName)) {
                                userOptional = apiService.findOneByThirdPartyId("google", oAuth2UserInfo.getId());
                                System.out.println("login with google");
                        } else if ("Line".equalsIgnoreCase(clientName)) {
                            userOptional = apiService.findOneByThirdPartyId("line", oAuth2UserInfo.getId());
                            System.out.println("login with line");
                        }else {
                                System.out.print("unknaow client");
                        }
                        System.out.println("1");
                } catch (URISyntaxException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                }
                System.out.println("2");
                String uuid = userOptional.getString("universallyUniqueIdentifier");
                String personnelId = userOptional.get("id").toString();
                String personnelHref = userOptional.getJSONObject("_links").getJSONObject("self").getString("href");
                
//      user.setProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
                
                
                
                
                user.setProviderId(oAuth2UserInfo.getId());
                user.setName(oAuth2UserInfo.getName());
				if(oAuth2UserInfo.getEmail()==null) {
					user.setEmail("test");
				}else {
					user.setEmail(oAuth2UserInfo.getEmail());
				}  
                user.setImageUrl(oAuth2UserInfo.getImageUrl());
                user.setUuid(uuid);
                user.setPersonnelId(personnelId);
                user.setPersonnelHref(personnelHref);
                user.setThirdParty(clientName);
                return UserPrincipal.create(user, oAuth2User.getAttributes());
//    	return null;
        }

//    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
//        User user = new User();
//
//        user.setProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
//        user.setProviderId(oAuth2UserInfo.getId());
//        user.setName(oAuth2UserInfo.getName());
//        user.setEmail(oAuth2UserInfo.getEmail());
//        user.setImageUrl(oAuth2UserInfo.getImageUrl());
//        return userRepository.save(user);
//    }
//
//    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
//        existingUser.setName(oAuth2UserInfo.getName());
//        existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
//        return userRepository.save(existingUser);
//    }
}
