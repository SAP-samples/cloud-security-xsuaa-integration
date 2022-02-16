package com.sap.cloud.security.xsuaa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static com.sap.cloud.security.config.cf.CFConstants.CLIENT_ID;
import static com.sap.cloud.security.config.cf.CFConstants.VCAP_SERVICES;
import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.*;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SystemStubsExtension.class)
class XsuaaServiceConfigurationFromEnvTest {
	XsuaaServiceConfigurationDefault cut;
	String vcapServiceCredentials = "{\"xsuaa\":[{\"credentials\":{\"apiurl\":\"https://api.mydomain.com\",\"tenantid\":\"tenant-id\",\"subaccountid\":\"subaccount-id\",\"clientid\":\"client-id\"},\"tags\":[\"xsuaa\"]}]}";

	@BeforeEach
	void setup(EnvironmentVariables environmentVariables) {
		cut = new XsuaaServiceConfigurationDefault();
		environmentVariables.set(VCAP_SERVICES, vcapServiceCredentials);
	}

	@Test
	void getProperty() {
		assertThat(cut.getProperty(API_URL)).isEqualTo("https://api.mydomain.com");
		assertThat(cut.getProperty(SUBACCOUNT_ID)).isEqualTo("subaccount-id");
		assertThat(cut.getProperty(TENANT_ID)).isEqualTo("tenant-id");
		assertThat(cut.getProperty(CLIENT_ID)).isEqualTo("client-id");
		assertThat(cut.getProperty("unknownProp")).isNull();
	}

	@Test
	void hasProperty() {
		assertThat(cut.hasProperty(API_URL)).isTrue();
		assertThat(cut.hasProperty(SUBACCOUNT_ID)).isTrue();
		assertThat(cut.hasProperty("unknownProp")).isFalse();
	}
}