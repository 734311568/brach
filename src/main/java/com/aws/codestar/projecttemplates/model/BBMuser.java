package com.aws.codestar.projecttemplates.model;

import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class BBMuser extends User {
	
	private static final long serialVersionUID = -3531439484732724601L;

	private final String uuid;
	private final String personnelId;
	private final String personnelHref;
	private final String thirdParty;
	private final String nickname;
	private final String email;

	public BBMuser(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked, Collection authorities,
			String uuid,String personnelId, String personnelHref, String thirdParty, String nickname,String email) {

		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);

		this.uuid = uuid;
		this.personnelId = personnelId;
		this.personnelHref = personnelHref;
		this.thirdParty = thirdParty;
		this.nickname = nickname;
		this.email = email;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public String getUuid() {
		return uuid;
	}

	public String getPersonnelId() {
		return personnelId;
	}

	public String getPersonnelHref() {
		return personnelHref;
	}

	public String getThirdParty() {
		return thirdParty;
	}

	public String getNickname() {
		return nickname;
	}

	public String getEmail() {
		return email;
	}

	@Override
	public String toString() {
		return "BBMuser [uuid=" + uuid + ", personnelId=" + personnelId + ", personnelHref=" + personnelHref
				+ ", thirdParty=" + thirdParty + ", nickname=" + nickname + ", email=" + email + "]";
	}

}