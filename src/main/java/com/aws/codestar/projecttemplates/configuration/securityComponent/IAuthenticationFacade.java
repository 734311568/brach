package com.aws.codestar.projecttemplates.configuration.securityComponent;

import org.springframework.security.core.Authentication;

public interface IAuthenticationFacade {
	Authentication getAuthentication();
}
