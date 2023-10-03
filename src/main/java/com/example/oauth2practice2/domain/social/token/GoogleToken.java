package com.example.oauth2practice2.domain.social.token;

import lombok.Getter;

@Getter
public class GoogleToken implements SocialToken{
    private String access_token;
    private String expires_in;
    private String scope;
    private String token_type;
    private String id_token;
    private String refresh_token;
    private String refresh_token_expires_in;

    @Override
    public boolean check(String provider) {
        return provider.equals("Google");
    }

    @Override
    public String getAccessToken() {
        return access_token;
    }
}
