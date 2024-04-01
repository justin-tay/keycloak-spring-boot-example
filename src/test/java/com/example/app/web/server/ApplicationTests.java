package com.example.app.web.server;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties.Provider;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;

@SpringBootTest
class ApplicationTests {

	@Configuration
	public static class TestConfiguration {

		public TestConfiguration(Optional<OAuth2ClientProperties> properties) {
			if (properties.isPresent()) {
				for (Provider provider : properties.get().getProvider().values()) {
					// Clear issuer-uri as it requires the authorization server to be up
					provider.setIssuerUri(null);
				}
			}
		}

	}

	@Test
	void contextLoads() {
	}

}
