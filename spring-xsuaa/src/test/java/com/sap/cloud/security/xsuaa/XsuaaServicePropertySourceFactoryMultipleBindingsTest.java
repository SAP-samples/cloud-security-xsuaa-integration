package com.sap.cloud.security.xsuaa;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.EncodedResource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.xsuaa.XsuaaServicePropertySourceFactory.CLIENT_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class XsuaaServicePropertySourceFactoryMultipleBindingsTest {
	XsuaaServicePropertySourceFactory cut = new XsuaaServicePropertySourceFactory();

	@Test
	public void ignoreApiAccessPlan() throws IOException {
		ResourceLoader resourceLoader = new DefaultResourceLoader();
		Resource resource = resourceLoader.getResource("classpath:vcap_multipleBindings.json");
		PropertySource propertySource = cut.createPropertySource(null, new EncodedResource(resource));
		assertThat(propertySource.getProperty(CLIENT_ID)).isEqualTo("client-id");
	}

	@Test
	public void doNotAllowBrokerAndApplicationPlan() {
		assertThrows(IllegalStateException.class, () -> {
			String vcapMultipleBindings = IOUtils.resourceToString("/vcap_multipleBindings.json", StandardCharsets.UTF_8);
			vcapMultipleBindings = vcapMultipleBindings.replace("apiaccess", "broker");
			Resource resource = new InputStreamResource(
					new ByteArrayInputStream(vcapMultipleBindings.getBytes(StandardCharsets.UTF_8)));
			cut.createPropertySource(null, new EncodedResource(resource));
		});
	}

	@Test
	public void acceptVcapServicesWithoutPlan() throws IOException {
		String vcapMinimalWoPlan = "{\"xsuaa\":[{\"credentials\":{\"clientid\":\"client-id\",\"clientsecret\":\"client-secret\"},\"tags\":[\"xsuaa\"]}]}";
		Resource resource = new InputStreamResource(
				new ByteArrayInputStream(vcapMinimalWoPlan.getBytes(StandardCharsets.UTF_8)));
		PropertySource propertySource = cut.createPropertySource(null, new EncodedResource(resource));
		assertThat(propertySource.getProperty(CLIENT_ID)).isEqualTo("client-id");
	}

}
