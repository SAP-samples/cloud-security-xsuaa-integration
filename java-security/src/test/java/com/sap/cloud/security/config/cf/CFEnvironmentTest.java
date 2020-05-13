package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;

import com.sap.cloud.security.json.JsonParsingException;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import java.io.IOException;
import java.util.Map;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class CFEnvironmentTest {

	@Rule
	public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

	private String vcapXsuaa;
	private String vcapMultipleXsuaa;
	private String vcapIas;
	private String vcapXsa;
	private CFEnvironment cut;

	public CFEnvironmentTest() throws IOException {
		vcapXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceSingleBinding.json", UTF_8);
		vcapMultipleXsuaa = IOUtils.resourceToString("/vcapXsuaaServiceMultipleBindings.json", UTF_8);
		vcapIas = IOUtils.resourceToString("/vcapIasServiceSingleBinding.json", UTF_8);
		vcapXsa = IOUtils.resourceToString("/vcapXsuaaXsaSingleBinding.json", UTF_8);
	}

	@Before
	public void setUp() {
		cut = CFEnvironment.getInstance((str) -> vcapXsuaa, (str) -> null);
	}

	@Test
	public void getInstance() {
		assertThat(CFEnvironment.getInstance()).isNotSameAs(CFEnvironment.getInstance());
		assertThat(cut.getType()).isEqualTo(Environment.Type.CF);
	}

	@Test
	public void getCFServiceConfigurationAndCredentialsAsMap() {
		String vcapServices = vcapXsuaa;
		JsonObject serviceJsonObject = new DefaultJsonObject(vcapServices).getJsonObjects(Service.XSUAA.getCFName())
				.get(0);
		Map<String, String> xsuaaConfigMap = serviceJsonObject.getKeyValueMap();
		Map<String, String> credentialsMap = serviceJsonObject.getJsonObject(CREDENTIALS).getKeyValueMap();

		assertThat(xsuaaConfigMap.size()).isEqualTo(4);
		assertThat(credentialsMap.size()).isEqualTo(10);
		assertThat(credentialsMap.get(CLIENT_SECRET)).isEqualTo("secret");
	}

	@Test
	public void getCorruptConfiguration_raisesException() {
		String xsuaaBinding = "{\"xsuaa\": [{ \"credentials\": null }]}";

		assertThatThrownBy(() -> {
			cut = CFEnvironment.getInstance((str) -> xsuaaBinding, (str) -> null);
		}).isInstanceOf(JsonParsingException.class).hasMessageContainingAll(
				"The credentials of 'VCAP_SERVICES' can not be parsed for service 'XSUAA'",
				"Please check the service binding.");
	}

	@Test
	public void getConfigurationOfOneIasInstance() {
		cut = CFEnvironment.getInstance((str) -> vcapIas, (str) -> null);
		assertThat(cut.getIasConfiguration()).isSameAs(cut.getIasConfiguration());
		assertThat(cut.getIasConfiguration().getService()).isEqualTo(Service.IAS);
		assertThat(cut.getIasConfiguration().getClientId()).isEqualTo("T000310");
		assertThat(cut.getIasConfiguration().getClientSecret()).startsWith("pCghfbrL");
		assertThat(cut.getIasConfiguration().getUrl().toString()).isEqualTo("https://myauth.com");
		assertThat(cut.getIasConfiguration().isLegacyMode()).isFalse();

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isNull();
	}

	@Test
	public void getConfigurationOfOneXsuaaInstance() {
		assertThat(cut.getXsuaaConfiguration()).isSameAs(cut.getXsuaaConfiguration());
		assertThat(cut.getXsuaaConfiguration().getService()).isEqualTo(Service.XSUAA);
		assertThat(cut.getXsuaaConfiguration().getClientId()).isEqualTo("clientId");
		assertThat(cut.getXsuaaConfiguration().getClientSecret()).isEqualTo("secret");
		assertThat(cut.getXsuaaConfiguration().getProperty(XSUAA.UAA_DOMAIN)).isEqualTo("auth.com");
		assertThat(cut.getXsuaaConfiguration().getProperty(XSUAA.APP_ID)).isEqualTo("java-hello-world");
		assertThat(cut.getXsuaaConfiguration().getUrl().toString()).isEqualTo("https://paastenant.auth.com");
		assertThat(cut.getXsuaaConfiguration().isLegacyMode()).isFalse();

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(1);
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isSameAs(cut.getXsuaaConfiguration());

		assertThat(cut.getIasConfiguration()).isNull();
	}

	@Test
	public void getConfigurationOfXsuaaInstanceInXsaSystem() {
		environmentVariables.set(VCAP_SERVICES, vcapXsa);
		environmentVariables.set(VCAP_APPLICATION, "{\"xs_api\": \"anyvalue\"}");
		assertThat(System.getenv(VCAP_APPLICATION)).isNotNull();
		cut = CFEnvironment.getInstance();

		assertThat(cut.getXsuaaConfiguration().getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(cut.getXsuaaConfiguration().getProperty(SERVICE_PLAN))).isEqualTo(Plan.SPACE);
		assertThat(cut.getXsuaaConfiguration().getClientId()).isEqualTo("sb-java-hello-world!i1");
		assertThat(cut.getXsuaaConfiguration().getProperty(XSUAA.APP_ID)).isEqualTo("java-hello-world!i1");
		assertThat(cut.getXsuaaConfiguration().getClientSecret()).startsWith("fxnWLHqLh6KC0Wp/bbv8Gwbu50OEbpS");
		assertThat(cut.getXsuaaConfiguration().getUrl().toString())
				.isEqualTo("https://xsa-test.c.eu-de-2.cloud.sap:30132/uaa-security");
		assertThat(cut.getXsuaaConfiguration().isLegacyMode()).isTrue();

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(1);
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isSameAs(cut.getXsuaaConfiguration());
	}

	@Test
	public void getConfigurationOfMultipleInstance() {
		cut = CFEnvironment.getInstance((str) -> vcapMultipleXsuaa, (str) -> null);

		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(2);
		OAuth2ServiceConfiguration appServConfig = cut.getXsuaaConfiguration();
		OAuth2ServiceConfiguration brokerServConfig = cut.getXsuaaConfigurationForTokenExchange();

		assertThat(appServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(appServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.APPLICATION);

		assertThat(brokerServConfig).isNotEqualTo(appServConfig);
		assertThat(brokerServConfig.getService()).isEqualTo(Service.XSUAA);
		assertThat(Plan.from(brokerServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaConfigurationForTokenExchange());
	}

	@Test
	public void getConfigurationByPlan() {
		cut = CFEnvironment.getInstance((str) -> vcapMultipleXsuaa, (str) -> null);

		OAuth2ServiceConfiguration appServConfig = cut.loadForServicePlan(Service.XSUAA,
				Plan.APPLICATION);
		OAuth2ServiceConfiguration brokerServConfig = cut.loadForServicePlan(Service.XSUAA,
				Plan.BROKER);

		assertThat(Plan.from(appServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.APPLICATION);
		assertThat(appServConfig).isSameAs(cut.getXsuaaConfiguration());

		assertThat(Plan.from(brokerServConfig.getProperty(SERVICE_PLAN))).isEqualTo(Plan.BROKER);
		assertThat(brokerServConfig).isSameAs(cut.getXsuaaConfigurationForTokenExchange());
	}

	@Test
	public void getXsuaaServiceConfiguration_usesSystemProperties() {
		cut = CFEnvironment.getInstance((str) -> vcapXsuaa, (str) -> vcapMultipleXsuaa);

		OAuth2ServiceConfiguration serviceConfiguration = cut.getXsuaaConfiguration();

		assertThat(serviceConfiguration).isNotNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(2);
	}

	@Test
	public void getServiceConfiguration_vcapServicesNotAvailable_returnsNull() {
		cut = CFEnvironment.getInstance((str) -> null, (str) -> null);

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isEqualTo(0);
		assertThat(cut.getXsuaaConfigurationForTokenExchange()).isNull();
		assertThat(cut.loadForServicePlan(Service.IAS, Plan.DEFAULT)).isNull();
		assertThat(CFEnvironment.getInstance().getXsuaaConfiguration()).isNull();
		assertThat(cut.getIasConfiguration()).isNull();
	}

	@Test
	public void loadXsuaa_UseApplicationOverBroker() {
		String allBindings = "{\"xsuaa\": ["
				+ "{\"plan\": \"broker\", \"credentials\": {}},"
				+ "{\"plan\": \"application\", \"credentials\": {}}]}";
		cut = CFEnvironment.getInstance((str) -> allBindings, (str) -> null);

		OAuth2ServiceConfiguration config = cut.getXsuaaConfiguration();
		assertThat(Plan.from(config.getProperty(SERVICE_PLAN))).isEqualTo(Plan.APPLICATION);
	}

	@Test
	public void loadXsuaaLegacy() {
		String allBindings = "{\"xsuaa\": ["
				+ "{\"plan\": \"default\", \"credentials\": {}},"
				+ "{\"plan\": \"space\", \"credentials\": {}}]}";
		cut = CFEnvironment.getInstance((str) -> allBindings, (str) -> null);

		OAuth2ServiceConfiguration config = cut.getXsuaaConfiguration();
		assertThat(Plan.from(config.getProperty(SERVICE_PLAN))).isEqualTo(Plan.SPACE);
	}

	@Test
	public void getXsuaaConfiguration_noVcapServices_doesNotThrowExceptions() {
		cut = CFEnvironment.getInstance((any) -> null, (any) -> null);

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isZero();
	}

	@Test
	public void getXsuaaConfiguration_vcapServicesEmptyString_doesNotThrowExceptions() {
		cut = CFEnvironment.getInstance((any) -> "", (any) -> "");

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isZero();
	}

	@Test
	public void getXsuaaConfiguration_vcapServicesEmptyJson_doesNotThrowExceptions() {
		cut = CFEnvironment.getInstance((any) -> "{}", (any) -> "{}");

		assertThat(cut.getXsuaaConfiguration()).isNull();
		assertThat(cut.getNumberOfXsuaaConfigurations()).isZero();
	}
}