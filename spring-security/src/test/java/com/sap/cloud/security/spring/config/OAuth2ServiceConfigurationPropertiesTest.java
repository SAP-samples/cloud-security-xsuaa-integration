package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFConstants.XSUAA;
import org.junit.jupiter.api.Test;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static org.junit.jupiter.api.Assertions.*;

class OAuth2ServiceConfigurationPropertiesTest {
	OAuth2ServiceConfigurationProperties cutIas = new OAuth2ServiceConfigurationProperties(Service.IAS);
	OAuth2ServiceConfigurationProperties cutXsuaa = new OAuth2ServiceConfigurationProperties(Service.XSUAA);
	private static final String ANY_VALUE = "anyValue";

	@Test
	void setGetClientId() {
		cutIas.setClientId(ANY_VALUE);
		assertEquals(ANY_VALUE, cutIas.getClientId());
		assertTrue(cutIas.hasProperty(CFConstants.CLIENT_ID));
		assertEquals(ANY_VALUE, cutIas.getProperty(CFConstants.CLIENT_ID));

		cutXsuaa.setClientId(ANY_VALUE);
		assertEquals(ANY_VALUE, cutXsuaa.getClientId());
		assertTrue(cutXsuaa.hasProperty(CFConstants.CLIENT_ID));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(CFConstants.CLIENT_ID));
	}

	@Test
	void setGetClientSecret() {
		cutIas.setClientSecret(ANY_VALUE);
		assertEquals(ANY_VALUE, cutIas.getClientSecret());
		assertTrue(cutIas.hasProperty(CLIENT_SECRET));
		assertEquals(ANY_VALUE, cutIas.getProperty(CLIENT_SECRET));

		cutXsuaa.setClientSecret(ANY_VALUE);
		assertEquals(ANY_VALUE, cutXsuaa.getClientSecret());
		assertTrue(cutXsuaa.hasProperty(CLIENT_SECRET));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(CLIENT_SECRET));
	}

	@Test
	void setGetUrl() {
		cutIas.setUrl(ANY_VALUE);
		assertEquals(ANY_VALUE, cutIas.getUrl().toString());
		assertTrue(cutIas.hasProperty(URL));
		assertEquals(ANY_VALUE, cutIas.getProperty(URL));

		cutXsuaa.setUrl(ANY_VALUE);
		assertEquals(ANY_VALUE, cutXsuaa.getUrl().toString());
		assertTrue(cutXsuaa.hasProperty(URL));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(URL));
	}

	@Test
	void getProperties() {
		cutIas.setClientId(ANY_VALUE);
		cutIas.setClientSecret(ANY_VALUE);
		assertEquals(ANY_VALUE, cutIas.getProperties().get(CLIENT_ID));
		assertEquals(ANY_VALUE, cutIas.getProperties().get(CLIENT_SECRET));
		assertNull(cutIas.getProperties().get(URL));
	}

	@Test
	void setGetService() {
		assertEquals(Service.IAS, cutIas.getService());
		assertEquals(Service.XSUAA, cutXsuaa.getService());
	}

	@Test
	void setGetUaaDomain() {
		cutXsuaa.setUaaDomain(ANY_VALUE);
		assertTrue(cutXsuaa.hasProperty(XSUAA.UAA_DOMAIN));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(XSUAA.UAA_DOMAIN));
	}

	@Test
	void setGetXsAppName() {
		cutXsuaa.setXsAppName(ANY_VALUE);
		assertTrue(cutXsuaa.hasProperty(XSUAA.APP_ID));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(XSUAA.APP_ID));
	}

	@Test
	void setGetVerificationKey() {
		cutXsuaa.setVerificationKey(ANY_VALUE);
		assertTrue(cutXsuaa.hasProperty(XSUAA.VERIFICATION_KEY));
		assertEquals(ANY_VALUE, cutXsuaa.getProperty(XSUAA.VERIFICATION_KEY));
	}

	@Test
	void isLegacyMode() {
		assertFalse(cutXsuaa.isLegacyMode());
	}

	@Test
	void setGetConfiguration() {
		assertEquals(cutIas.getConfiguration(), cutIas.getConfiguration());
		assertNotEquals(cutIas.getConfiguration(), cutXsuaa.getConfiguration());
	}
}