package com.example.app.web.server.api;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Account endpoint.
 */
@RestController
public class AccountController {
	private final WebClient webClient;

	public AccountController(WebClient webClient) {
		this.webClient = webClient;
	}

	@GetMapping(path = "/account", produces = MediaType.APPLICATION_JSON_VALUE)
	public String account(@RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient) {
		String issuerUri = authorizedClient.getClientRegistration().getProviderDetails().getIssuerUri();
		String resourceUri = issuerUri + "/account/?userProfileMetadata=true";
		return webClient.get().uri(resourceUri).accept(MediaType.APPLICATION_JSON)
				.attributes(oauth2AuthorizedClient(authorizedClient)).retrieve().bodyToMono(String.class).block();
	}
}
