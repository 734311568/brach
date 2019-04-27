package com.aws.codestar.projecttemplates.model;
import com.aws.codestar.projecttemplates.configuration.oauth2Component.AuthProvider;

public class User {    
    private Long id;
    private String name;
    private String email;
    private String imageUrl;    
    private Boolean emailVerified = false;
    private String password;
    private AuthProvider provider;
    private String providerId;
    private String uuid;
    private String personnelId;
    private String personnelHref;
    private String thirdParty;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
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

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public AuthProvider getProvider() {
        return provider;
    }

    public void setProvider(AuthProvider provider) {
        this.provider = provider;
    }

    public String getProviderId() {
        return providerId;
    }

    public void setProviderId(String providerId) {
        this.providerId = providerId;
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

	public String getThirdParty() {
		return thirdParty;
	}

	public void setThirdParty(String thirdParty) {
		this.thirdParty = thirdParty;
	}

	@Override
	public String toString() {
		return "User [id=" + id + ", name=" + name + ", email=" + email + ", imageUrl=" + imageUrl + ", emailVerified="
				+ emailVerified + ", password=" + password + ", provider=" + provider + ", providerId=" + providerId
				+ ", uuid=" + uuid + ", personnelId=" + personnelId + ", personnelHref=" + personnelHref
				+ ", thirdParty=" + thirdParty + "]";
	}
    
}
