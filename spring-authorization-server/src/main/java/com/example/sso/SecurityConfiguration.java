package com.example.sso;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.beans.factory.config.BeanDefinition.ROLE_INFRASTRUCTURE;

@Configuration
public class SecurityConfiguration {

	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		return http.formLogin(Customizer.withDefaults()).build();
	}

	@Bean
	@Order(2)
	public SecurityFilterChain standardSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests((authorize) -> authorize.anyRequest().authenticated())
			.formLogin(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		// @formatter:off
		RegisteredClient webClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("87fe78e0-ad84-42cf-a55e-309e110e40e8")
				.clientSecret("{noop}7nLmy2s.5Pv3-hEXvMbQtg-~5V3_Z0E6VK")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/facility-request")
				.scope(OidcScopes.OPENID)
				.scope("profile")
				.scope("offline_access")
				.scope("api://facility-inventory/Facility.Read")
				.scope("api://facility-inventory/Facility.Write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
				.build();
		RegisteredClient hrClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("b7d58b57-a71f-4115-b501-fa84647200a6")
				.clientSecret("{noop}S-a18kTmeCFE0b2S_wtf9.psA.q7PhtkQ~")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/facility-inventory")
				.scope("api://hr/HealthInformation:Read")
				.scope("api://hr/.default")
				.build();
		// @formatter:on
		return new InMemoryRegisteredClientRepository(webClient, hrClient);
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		// @formatter:off
		RSAKey rsaKey = new RSAKey.Builder(publicKey)
				.privateKey(privateKey)
				.keyID(UUID.randomUUID().toString())
				.build();
		// @formatter:on
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	@Bean
	public JwtDecoder jwtDecoder(KeyPair keyPair) {
		return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
	}

	@Bean
	public ProviderSettings providerSettings() {
		return ProviderSettings.builder().issuer("http://auth-server:9000").build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user1 = User.withDefaultPasswordEncoder()
				.username("user1@springonedemo20210830.onmicrosoft.com")
				.password("Voxu8138E")
				.roles("USER")
				.build();
		UserDetails user2 = User.withDefaultPasswordEncoder()
				.username("user2@springonedemo20210830.onmicrosoft.com")
				.password("Qava8536G")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user1, user2);
	}

	@Bean
	@Role(ROLE_INFRASTRUCTURE)
	KeyPair generateRsaKey() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

}
