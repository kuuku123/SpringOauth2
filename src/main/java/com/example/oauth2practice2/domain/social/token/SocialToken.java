package com.example.oauth2practice2.domain.social.token;

public interface SocialToken {

    boolean check(String provider);
    String getAccessToken();
}
