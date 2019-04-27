package com.aws.codestar.projecttemplates.configuration.securityComponent;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.aws.codestar.projecttemplates.model.BBMuser;
import com.aws.codestar.projecttemplates.service.ApiService;

@Import(ApiService.class)
@Component
public class UserDetailServiceImpl implements UserDetailsService {

	@Autowired
	ApiService apiService;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		List<SimpleGrantedAuthority> authorities = new ArrayList<>();
		JSONObject userInfo = null;
		BBMuser user = null;
		if ("".equals(username)) {
			throw new BadCredentialsException("Authentication failed");
		}

		try {
			userInfo = apiService.findOneByEmail(username);
			authorities.add(new SimpleGrantedAuthority("ROLE_USER"));	
			
			String uuid =userInfo.getString("universallyUniqueIdentifier");
			String personnelId =userInfo.get("id").toString();
			String personnelHref =userInfo.getJSONObject("_links").getJSONObject("self").getString("href");
			String thirdParty="";
			String nickname= userInfo.getString("nickname");
			String email=userInfo.getString("email");			
			String password = "$2a$10$BFrkcGn77/8lbzyqhPpwQeu0.00jtw4qBPgQ4lD/AFzTXDXFSA5hG";
			
			user = new BBMuser(
					 username,password, 
					 true, true, true, true,authorities, 
					 uuid,personnelId,personnelHref, thirdParty, nickname,email);
			
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
//		if (username.equals("redan")) {
//			authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
//			return new UsernamePasswordAuthenticationToken(username, "0", authorities);
//		}
		return user;
	}

}
