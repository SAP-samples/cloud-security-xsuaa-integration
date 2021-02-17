package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.validation.ValidationListener;
import com.sap.cloud.security.spring.token.authentication.HybridJwtDecoder;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class JwtDecoderBuilderTest {
	JwtDecoderBuilder cut = new JwtDecoderBuilder();

	@Test
	void withCacheConfiguration() {
		CacheConfiguration cacheConfiguration = Mockito.mock(CacheConfiguration.class);
		assertNotNull(cut.withCacheConfiguration(cacheConfiguration));
	}

	@Test
	void withHttpClient() {
		CloseableHttpClient mockHttpClient = Mockito.mock(CloseableHttpClient.class);
		assertNotNull(cut.withHttpClient(mockHttpClient));
	}

	@Test
	void buildHybridWithoutConfiguration_IllegalArgumentException() {
		assertThrows(IllegalArgumentException.class, () -> cut.buildHybrid());
	}

	@Test
	void buildHybridWithoutConfiguration() {
		OAuth2ServiceConfiguration iasConfiguration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withClientId("clientId")
				.withProperty(CFConstants.URL, "https://domain.myauth.com")
				// .withProperty(CFConstants.IAS.DOMAIN, "myauth.com")
				.build();

		cut.withIasServiceConfiguration(iasConfiguration);
		cut.withXsuaaServiceConfiguration(iasConfiguration);
		cut.withValidationListener(Mockito.mock(ValidationListener.class));
		JwtDecoder decoder = cut.buildHybrid();
		assertTrue(decoder instanceof HybridJwtDecoder);
	}

	@Test
	void buildHybridWithMultipleXsuaaConfigurations() {
		OAuth2ServiceConfiguration iasConfiguration = OAuth2ServiceConfigurationBuilder
				.forService(Service.IAS)
				.withClientId("clientId")
				.withProperty(CFConstants.URL, "https://domain.myauth.com")
				// .withProperty(CFConstants.IAS.DOMAIN, "myauth.com")
				.build();

		OAuth2ServiceConfiguration otherXsuaaConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(otherXsuaaConfiguration.getClientId()).thenReturn("otherClientId");

		List<OAuth2ServiceConfiguration> xsuaaConfigurations = new ArrayList<>();
		xsuaaConfigurations.add(iasConfiguration);
		xsuaaConfigurations.add(otherXsuaaConfiguration);

		cut.withIasServiceConfiguration(iasConfiguration);
		cut.withXsuaaServiceConfigurations(xsuaaConfigurations);
		cut.withValidationListener(Mockito.mock(ValidationListener.class));
		JwtDecoder decoder = cut.buildHybrid();
		assertTrue(decoder instanceof HybridJwtDecoder);
	}
}