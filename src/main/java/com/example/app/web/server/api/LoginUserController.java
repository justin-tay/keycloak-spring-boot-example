package com.example.app.web.server.api;

import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Login user endpoint.
 */
@RestController
public class LoginUserController {

	@GetMapping(path = "/login-user", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, Object> loginUser(@AuthenticationPrincipal OidcUser principal) {
		return principal.getClaims();
	}

}
