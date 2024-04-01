package com.example.app.web.server.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Web security configuration.
 */
@Configuration
public class WebSecurityConfiguration {

	private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

	/**
	 * Gets the JWKS for encryption/decryption and signing/verification.
	 * @param resourceLoader the resource loader
	 * @param applicationProperties the application properties
	 * @return the JWKS
	 * @throws IOException the exception
	 * @throws ParseException the exception
	 */
	@Bean
	JWKSet jwks(ResourceLoader resourceLoader, ApplicationProperties applicationProperties)
			throws IOException, ParseException {
		try (InputStream inputStream = resourceLoader.getResource(applicationProperties.getJwks()).getInputStream()) {
			return JWKSet.load(inputStream);
		}
	}

	/**
	 * Configure the security filter chain.
	 * @param http the http security
	 * @param jwks the JWKS
	 * @param clientRegistrationRepository the client registration repository
	 * @return the security filter chain
	 * @throws Exception the exception
	 */
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, JWKSet jwks,
			ClientRegistrationRepository clientRegistrationRepository) throws Exception {
		DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = accessTokenResponseClient(jwks);
		return http
			.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
				.requestMatchers(new AntPathRequestMatcher("/oauth2/jwks"))
				.anonymous())
			.authorizeHttpRequests(
					authorizeHttpRequests -> authorizeHttpRequests.requestMatchers(new AntPathRequestMatcher("/**"))
						.authenticated())
			.oauth2Login(oauth2Login -> oauth2Login
				.tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenResponseClient(accessTokenResponseClient))
				.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.oidcUserService(oidcUserService())))
			.oidcLogout(oidcLogout -> oidcLogout.backChannel(withDefaults()))
			.logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)))
			.with(new DefaultLoginPageConfigurer<>(),
					defaultLoginPage -> defaultLoginPage.withObjectPostProcessor(new ObjectPostProcessor<Object>() {
						@Override
						public <O> O postProcess(O object) {
							if (object instanceof DefaultLoginPageGeneratingFilter filter) {
								// Configure this so the default login page generates the
								// logout message after
								// the post logout redirect
								filter.setLogoutSuccessUrl("/login?logout");
							}
							return object;
						}
					}))
			.build();
	}

	/**
	 * Configure the JWT decoder used to decode the ID Token.
	 * @return the jwt decoder factory to decode the ID Token
	 */
	@Bean
	JwtDecoderFactory<ClientRegistration> jwtDecoderFactory() {
		/*
		 * The default implementation is OidcIdTokenDecoderFactory but its customization
		 * is limited.
		 */
		return clientRegistration -> {
			return jwtDecoders.computeIfAbsent(clientRegistration.getRegistrationId(), key -> {
				DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
				JWSVerificationKeySelector<SecurityContext> jwsKeySelector;
				JWKSource<SecurityContext> jwkSource = jwkSource(clientRegistration);
				jwsKeySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new JWKSource<SecurityContext>() {
					@Override
					public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
						List<JWK> jwk = jwkSource.get(jwkSelector, context);
						return jwk.stream().filter(key -> {
							return KeyUse.SIGNATURE.equals(key.getKeyUse());
						}).toList();
					}
				});
				jwtProcessor.setJWSKeySelector(jwsKeySelector);
				return new NimbusJwtDecoder(jwtProcessor);
			});
		};
	}

	/**
	 * Gets the jwk source to use for a client registration.
	 * @param clientRegistration the client registration
	 * @return the jwk source
	 */
	private JWKSource<SecurityContext> jwkSource(ClientRegistration clientRegistration) {
		String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
		try {
			return new RemoteJWKSet<SecurityContext>(new URL(jwkSetUri));
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Gets the oidc logout success handler that calls the OpenID end_session_endpoint.
	 * @param clientRegistrationRepository
	 * @return
	 */
	private LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository) {
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(
				clientRegistrationRepository);
		oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/login?logout");
		return oidcLogoutSuccessHandler;
	}

	/**
	 * Gets the access token response client configured for private_key_jwt
	 * authentication.
	 * @param jwks the JWKS
	 * @return the access token response client
	 */
	private DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient(JWKSet jwks) {
		Function<ClientRegistration, JWK> jwkResolver = clientRegistration -> jwks.getKeys()
			.stream()
			.filter(jwk -> KeyUse.SIGNATURE.equals(jwk.getKeyUse()))
			.findFirst()
			.get();
		NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest> parametersConverter = new NimbusJwtClientAuthenticationParametersConverter<>(
				jwkResolver);

		OAuth2AuthorizationCodeGrantRequestEntityConverter authorizationCodeGrantRequestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
		authorizationCodeGrantRequestEntityConverter.addParametersConverter(parametersConverter);

		DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
		accessTokenResponseClient.setRequestEntityConverter(authorizationCodeGrantRequestEntityConverter);
		return accessTokenResponseClient;
	}

	/**
	 * Gets the OAuth2UserService that processes the tokens to add the granted
	 * authorities.
	 * @return the oidc user service
	 */
	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcUserService delegate = new OidcUserService();
		final JwtDecoderFactory<ClientRegistration> accessTokenDecoderFactory = clientRegistration -> {
			String issuerUri = clientRegistration.getProviderDetails().getIssuerUri();
			NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
			jwtDecoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));
			return jwtDecoder;
		};

		return (userRequest) -> {
			OidcUser oidcUser = delegate.loadUser(userRequest);

			Set<GrantedAuthority> authorities = new HashSet<>();

			JwtDecoder jwtDecoder = accessTokenDecoderFactory.createDecoder(userRequest.getClientRegistration());
			Jwt jwt = jwtDecoder.decode(userRequest.getAccessToken().getTokenValue());
			addAuthorities(authorities, jwt, "realm_access", "ROLE_");

			OidcIdToken idToken = userRequest.getIdToken();
			addAuthorities(authorities, idToken, "realm_access", "ROLE_");

			authorities.addAll(oidcUser.getAuthorities());

			return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
		};
	}

	/**
	 * Add authorities from token.
	 * @param authorities to add to
	 * @param token to read from
	 * @param claim to read from that contains the roles
	 * @param authorityPrefix the prefix to prepend to the authority name
	 */
	private void addAuthorities(Set<GrantedAuthority> authorities, ClaimAccessor token, String claim,
			String authorityPrefix) {
		Map<String, Object> realmAccess = token.getClaimAsMap(claim);
		if (realmAccess != null) {
			if (realmAccess.get("roles") instanceof Collection<?> roles) {
				roles.stream()
					.map(value -> authorityPrefix + value.toString())
					.map(SimpleGrantedAuthority::new)
					.forEach(authorities::add);
			}
		}
	}

}
