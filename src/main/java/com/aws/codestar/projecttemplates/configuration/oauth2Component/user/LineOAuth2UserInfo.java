package com.aws.codestar.projecttemplates.configuration.oauth2Component.user;

import java.util.Map;

public class LineOAuth2UserInfo extends OAuth2UserInfo {

    public LineOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return attributes.get("userId").toString();
    }

    @Override
    public String getName() {
        return (String) attributes.get("displayName");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("pictureUrl");
    }

	@Override
	public String getEmail() {
		// TODO Auto-generated method stub
		return null;
	}
}
