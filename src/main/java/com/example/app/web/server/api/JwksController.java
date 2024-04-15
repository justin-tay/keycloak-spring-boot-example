package com.example.app.web.server.api;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * JWKS endpoint.
 */
@RestController
public class JwksController {
	private JWKSet jwkset;

	public JwksController(JWKSet jwkset) {
		this.jwkset = jwkset;
	}

	@GetMapping(path = "/oauth2/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
	public String jwks() {
		return jwkset.toString();
	}
}
