package com.example.oauth2practice2.domain.social;

import com.example.oauth2practice2.domain.jwt.JwtDto;
import com.example.oauth2practice2.domain.member.SignUpForm;
import com.example.oauth2practice2.domain.social.token.GoogleToken;
import com.example.oauth2practice2.domain.social.token.KakaoToken;
import com.example.oauth2practice2.domain.social.token.SocialToken;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
@Service
@RequiredArgsConstructor
public class SocialLoginService {
    private final InMemoryClientRegistrationRepository clientRegistrationRepository;

    public SignUpForm signIn(String providerName, String code){
        ClientRegistration provider = clientRegistrationRepository.findByRegistrationId(providerName);
        SocialToken tokens = getTokens(provider, code);
        return getFormFromUserProfile(provider, tokens.getAccessToken());
    }

    private SignUpForm getFormFromUserProfile(ClientRegistration provider, String token) {
        Map<String, Object> map = (Map<String, Object>) getUserAttributes(provider, token);
        OAuth2Attributes attributes = OAuth2Attributes.of(provider.getRegistrationId(), map);
        return new SignUpForm(attributes.getEmail(), null, attributes.getName());
    }

    private Map<?, ?> getUserAttributes(ClientRegistration provider, String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(provider.getProviderDetails().getUserInfoEndpoint().getUri(),
            HttpMethod.GET, request, String.class);
        try {
            return new ObjectMapper().readValue(response.getBody(), Map.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private SocialToken getTokens(ClientRegistration provider, String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(tokenRequest(provider, code), headers);
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.postForEntity(provider.getProviderDetails().getTokenUri(),
            request, String.class);
        Class<? extends SocialToken> detailToken = getDetailToken(provider.getClientName());
        try {
            return new ObjectMapper().readValue(response.getBody(), detailToken);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private MultiValueMap<String, String> tokenRequest(ClientRegistration provider, String code) {
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("code", code);
        map.add("grant_type", provider.getAuthorizationGrantType().getValue());
        map.add("redirect_uri", provider.getRedirectUri());
        map.add("client_id", provider.getClientId());
        map.add("client_secret", provider.getClientSecret());
        return map;
    }

    public String tryOAuth2(String providerName) {
        ClientRegistration provider = clientRegistrationRepository.findByRegistrationId(providerName);
        String authorizationUri = provider.getProviderDetails().getAuthorizationUri();
        UriComponents uri = UriComponentsBuilder.fromHttpUrl(authorizationUri)
                .queryParam("client_id", provider.getClientId())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", provider.getRedirectUri())
                .queryParam("scope", String.join("%20", provider.getScopes()))
                .queryParam("state","randomvalue")
                .build(true);
        return uri.toUriString();
    }

    public ResponseEntity<JwtDto> connectToSocialSignIn(String providerName, String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        HttpEntity<String> request = new HttpEntity<>(code, headers);
        RestTemplate restTemplate = new RestTemplate();
        return restTemplate.postForEntity(
            "http://localhost:8080/login/social/" + providerName,
            request, JwtDto.class);
    }

    private Class<? extends SocialToken> getDetailToken(String provider) {
        if (provider.equals("Kakao")) {
            return KakaoToken.class;
        }
        if (provider.equals("Google")) {
            return GoogleToken.class;
        }
        return null;
    }
}
