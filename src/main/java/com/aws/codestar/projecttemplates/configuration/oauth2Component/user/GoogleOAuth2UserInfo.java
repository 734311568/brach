package com.aws.codestar.projecttemplates.configuration.oauth2Component.user;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class GoogleOAuth2UserInfo implements OidcUser{

	private String id;
	private String name;
	private String email;
	private String imageUrl;
	private Collection<? extends GrantedAuthority> authorities;
	private Map<String, Object> attributes;	
	private Map<String, Object> claims;
	private OidcUserInfo userInfo;
	private OidcIdToken idToken;
	private String uuid;
	private String personnelId;
	private String personnelHref;
	
	public GoogleOAuth2UserInfo() {
	}
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	@Override
	public String getName() {		
		return this.name;
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	@Override
	public OidcUserInfo getUserInfo() {
		return this.userInfo;
	}

	@Override
	public OidcIdToken getIdToken() {
		return idToken;
	}

	public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
		this.authorities = authorities;
	}

	public void setAttributes(Map<String, Object> attributes) {
		this.attributes = attributes;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setClaims(Map<String, Object> claims) {
		this.claims = claims;
	}

	public void setUserInfo(OidcUserInfo userInfo) {
		this.userInfo = userInfo;
	}

	public void setIdToken(OidcIdToken idToken) {
		this.idToken = idToken;
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getPersonnelId() {
		return personnelId;
	}

	public void setPersonnelId(String personnelId) {
		this.personnelId = personnelId;
	}

	public String getPersonnelHref() {
		return personnelHref;
	}

	public void setPersonnelHref(String personnelHref) {
		this.personnelHref = personnelHref;
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getImageUrl() {
		return imageUrl;
	}

	public void setImageUrl(String imageUrl) {
		this.imageUrl = imageUrl;
	}

	@Override
	public String toString() {
		return "GoogleOAuth2UserInfo [id=" + id + ", name=" + name + ", email=" + email + ", imageUrl=" + imageUrl
				+ ", authorities=" + authorities + ", attributes=" + attributes + ", claims=" + claims + ", userInfo="
				+ userInfo + ", idToken=" + idToken + ", uuid=" + uuid + ", personnelId=" + personnelId
				+ ", personnelHref=" + personnelHref + "]";
	}

	

	

	    
	    
    
    
    
}
