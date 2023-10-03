package com.example.oauth2practice2.domain.social.token;

import lombok.Getter;

@Getter
public class KakaoToken implements SocialToken{
    private String access_token;
    private String token_type;
    private String refresh_token;
    private String expires_in;
    private String scope;
    private String refresh_token_expires_in;

    @Override
    public boolean check(String provider) {
        return provider.equals("Kakao");
    }

    @Override
    public String getAccessToken() {
        return access_token;
    }
}
