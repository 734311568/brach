package com.aws.codestar.projecttemplates.configuration;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.aws.codestar.projecttemplates.configuration.oauth2Component.CustomOAuth2UserService;
import com.aws.codestar.projecttemplates.configuration.oauth2Component.CustomOidcUserService;
import com.aws.codestar.projecttemplates.configuration.oauth2Component.OAuth2SuccessHandler;
import com.aws.codestar.projecttemplates.configuration.securityComponent.BBMAuthEntryPoint;
import com.aws.codestar.projecttemplates.configuration.securityComponent.BBMSuccessHandler;
import com.aws.codestar.projecttemplates.configuration.securityComponent.UserDetailServiceImpl;
import com.aws.codestar.projecttemplates.service.ApiService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
	prePostEnabled = true,
	securedEnabled = true,
	jsr250Enabled = true)
@Import({
	ApiService.class,
	UserDetailServiceImpl.class,
	BBMSuccessHandler.class,
	BBMAuthEntryPoint.class,
	CustomOAuth2UserService.class,
	OAuth2SuccessHandler.class,
	CustomOidcUserService.class})
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	ApiService apiService;
	@Autowired
	UserDetailsService userDetailServiceImpl;
	@Autowired
	@Qualifier("BBMSuccessHandler")
	BBMSuccessHandler bBMSuccessHandler;
	@Autowired
	@Qualifier("BBMAuthEntryPoint")
	BBMAuthEntryPoint authEntryPoint;

	@Autowired
	CustomOAuth2UserService customOAuth2UserService;
	@Autowired
	OAuth2SuccessHandler oAuth2SuccessHandler;
	@Autowired
	CustomOidcUserService oidcUserService;

	@Bean(name = BeanIds.AUTHENTICATION_MANAGER)
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.cors().disable()
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/").permitAll()
			.antMatchers("/login").permitAll()
			.antMatchers("/originLogin").permitAll()
			.antMatchers("/oauth_login", "/loginFailure", "/")
			.permitAll()
			.and()
			.exceptionHandling()
			.authenticationEntryPoint(authEntryPoint)
			.and()
			.formLogin()
			.loginPage("/login")
			.loginProcessingUrl("/originLogin")
			.successHandler(bBMSuccessHandler)
			.failureForwardUrl("/registerview")
			.and()
			.oauth2Login()
			.authorizedClientService(authorizedClientService())
			.loginPage("/oauth_login")
			.authorizationEndpoint()
			.baseUri("/oauth2/authorize-client")
			.authorizationRequestRepository(authorizationRequestRepository())
			.and()
			.tokenEndpoint()
			.accessTokenResponseClient(accessTokenResponseClient())
			.and()
			.userInfoEndpoint()
			.userService(customOAuth2UserService)
			.oidcUserService(oidcUserService)
			.and()
			.defaultSuccessUrl("/loginSuccess")
			.successHandler(oAuth2SuccessHandler)
			.failureUrl("/loginFailure").failureHandler(new AuthenticationFailureHandler() {

			@Override
			public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException exception) throws IOException, ServletException {
				System.out.println("failure");
				exception.printStackTrace();

			}

		});

	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailServiceImpl);
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		auth.authenticationProvider(authenticationProvider);
	}

	@Bean
	public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
		return new HttpSessionOAuth2AuthorizationRequestRepository();
	}

	@Bean
	public OAuth2AuthorizedClientService authorizedClientService() {

		return new InMemoryOAuth2AuthorizedClientService(
			clientRegistrationRepository());
	}

	@Bean
	public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		return accessTokenResponseClient;
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		List<ClientRegistration> registrations = Arrays.asList("google", "facebook", "line").stream()
			.map(c -> getRegistration(c))
			.filter(registration -> registration != null)
			.collect(Collectors.toList());

		return new InMemoryClientRegistrationRepository(registrations);
	}

	private ClientRegistration getRegistration(String client) {
		String host = "localhost";
		try {
			host = InetAddress.getLocalHost().getHostAddress();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (client.equals("google")) {
			return CommonOAuth2Provider.GOOGLE.getBuilder(client)
				.clientId("368238083842-3d4gc7p54rs6bponn0qhn4nmf6apf24a.apps.googleusercontent.com")
				.clientSecret("2RM2QkEaf3A8-iCNqSfdG8wP")
				.redirectUriTemplate("http://"+host+":8080/login/oauth2/code/line")
				.build();
		}
		if (client.equals("facebook")) {
			return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
				.clientId("324639151729654")
				.clientSecret("3bb1ca5e40ad4930d70803ca804a92fa")
				.redirectUriTemplate("http://"+host+":8080/login/oauth2/code/line")
				.build();
		}
		
		if (client.equals("line")) {
			
//			 ClientRegistration.withRegistrationId("line")
//	         .clientId("{CHANNEL_ID}")
//	         .clientSecret("{CHANNEL_SECRET}")
//	         .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
//	         .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//	         .redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
//	         .scope("profile")
//	         .authorizationUri("https://access.line.me/oauth2/v2.1/authorize")
//	         .tokenUri("https://api.line.me/oauth2/v2.1/token")
//	         .userInfoUri("https://api.line.me/v2/profile")
//	         .userNameAttributeName("userId")
//	         .clientName("LINE")
//	         .build();
			
			/*
			clientId={Set your client id}
			clientSecret={Set your client secret}
			authorizationGrantType=authorization_code
			redirectUriTemplate={baseUrl}/login/oauth2/code/{registrationId}
			scope=profile
			clientName=LINE
			authorizationUri=https://access.line.me/oauth2/v2.1/authorize
			tokenUri=https://api.line.me/oauth2/v2.1/token
			jwkSetUri=https://api.line.me/oauth2/v2.1/verify
			userInfoUri=https://api.line.me/v2/profile
			userNameAttribute=userId 
			 */
			return ClientRegistration.withRegistrationId("line")
				.clientId("1553188053")
				.clientSecret("01bce112f9c36c7061e7a7399025039d")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//				.redirectUriTemplate("http://localhost:8080/login/oauth2/code/line")
				.redirectUriTemplate("http://"+host+":8080/login/oauth2/code/line")
				.scope("profile")
				.authorizationUri("https://access.line.me/oauth2/v2.1/authorize")
				.tokenUri("https://api.line.me/oauth2/v2.1/token")
				.userInfoUri("https://api.line.me/v2/profile")
				.userNameAttributeName("userId")
//				.jwkSetUri("https://api.line.me/oauth2/v2.1/verify")
				.clientName("LINE")
				.build();
		}
		return null;
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		new OAuth2ErrorHttpMessageConverter();
		return new BCryptPasswordEncoder();
	}

}
