package com.aws.codestar.projecttemplates.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

public class CustomAuthenticationProvider implements AuthenticationProvider {

			
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
       
        String password = authentication.getCredentials().toString();

        ArrayList<GrantedAuthority> roleList = new ArrayList<GrantedAuthority>();
		roleList.add(new SimpleGrantedAuthority("USER"));
	    UserDetails userDetails = new User("username", "username",  roleList);

        if (userDetails != null) {
            List<GrantedAuthority> grantedAuths = new ArrayList<GrantedAuthority>();
            for (GrantedAuthority auth : userDetails.getAuthorities()) {
                grantedAuths.add(auth);
            }

            if (grantedAuths.size() != 0) {
               
                return new UsernamePasswordAuthenticationToken(userDetails, password, roleList);

            } else {
                throw new DisabledException("No roles assigned");
            }

        }

        throw new DisabledException("User or password incorrect");

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
