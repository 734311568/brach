package com.aws.codestar.projecttemplates.controller;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.aws.codestar.projecttemplates.configuration.securityComponent.IAuthenticationFacade;

@RestController
public class SessionController {

	@Autowired
	RedisTemplate<String, Object> redisTemplate;

	@Autowired
	private IAuthenticationFacade authenticationFacade;

	@Autowired
	private AuthenticationManager authManager;

	@RequestMapping(value = "/signin/facebook", method = RequestMethod.GET)
	public String signInWithFacebook(String sid, String mail) {
		UsernamePasswordAuthenticationToken authReq = new UsernamePasswordAuthenticationToken(mail, sid);
		Authentication auth = authManager.authenticate(authReq);
		SecurityContext sc = SecurityContextHolder.getContext();
		sc.setAuthentication(auth);
		return "ok";
	}

	@RequestMapping(value = "/session/logout", method = RequestMethod.GET)
	public String sessionlogout() {
		SecurityContextHolder.clearContext();
		// Moreover they optionally invalidate the HttpSession:
		// if (invalidateHttpSession) {
		// HttpSession session = request.getSession(false);
		// if (session != null) {
		// session.invalidate();
		// }
		// }
		return "ok";
	}

//	@PreAuthorize("hasRole('ADMIN')")
	/*anonymousUser user*/
	@RequestMapping(value = "/test", method = RequestMethod.GET)
	public String test() {
		Authentication authentication = authenticationFacade.getAuthentication();
		return authentication.getName();
	}

	@PreAuthorize("hasRole('ADMIN')")
	@RequestMapping(value = "/listAllSession", method = RequestMethod.GET)
	public String listAllSession() {
		Set<String> redisKeys = redisTemplate.keys("*");
		// Store the keys in a List
		List<String> keysList = new ArrayList<>();
		Iterator<String> it = redisKeys.iterator();
		while (it.hasNext()) {
			String data = it.next();
			keysList.add(data);
		}
		return keysList.toString();
	}

	@PreAuthorize("hasRole('ADMIN')")
	@RequestMapping(value = "/deleteAllSession", method = RequestMethod.GET)
	public String deleteAllSession() {
		Set<String> redisKeys = redisTemplate.keys("*");
		// Store the keys in a List
		List<String> keysList = new ArrayList<>();
		Iterator<String> it = redisKeys.iterator();
		while (it.hasNext()) {
			String data = it.next();
			keysList.add(data);
		}
		redisTemplate.delete(keysList);
		return "done";
	}
}
