package com.aws.codestar.projecttemplates.configuration.oauth2Component;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import com.aws.codestar.projecttemplates.configuration.oauth2Component.user.GoogleOAuth2UserInfo;
import com.aws.codestar.projecttemplates.service.ApiService;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class CustomOidcUserService extends OidcUserService {

	@Autowired
    private ApiService apiService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
    	JSONObject userOptional = null;
    	OidcUser oidcUser = super.loadUser(userRequest);
        Map<String, Object> attributes = oidcUser.getAttributes();
        GoogleOAuth2UserInfo userInfo = new GoogleOAuth2UserInfo();
        
        List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        userInfo.setAttributes(attributes);
        userInfo.setAuthorities(authorities);
        try {
        	System.out.println(oidcUser.getName());
        	userOptional = apiService.findOneByThirdPartyId("google", oidcUser.getName());
		} catch (IOException | URISyntaxException e) {
			e.printStackTrace();
		}
        System.out.println(userOptional);
        String uuid = userOptional.getString("universallyUniqueIdentifier");
        String personnelId = userOptional.get("id").toString();
        String personnelHref = userOptional.getJSONObject("_links").getJSONObject("self").getString("href");
        userInfo.setUuid(uuid);
        userInfo.setPersonnelId(personnelId);
        userInfo.setPersonnelHref(personnelHref);
        userInfo.setUserInfo(oidcUser.getUserInfo());
        
        userInfo.setEmail((String) attributes.get("email"));
        userInfo.setId((String) attributes.get("sub"));
        userInfo.setImageUrl((String) attributes.get("picture"));
        userInfo.setName((String) attributes.get("name"));
        return userInfo;
    }

}
