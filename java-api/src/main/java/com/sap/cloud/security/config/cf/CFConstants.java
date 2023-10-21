/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.cf;

/**
 * Constants that simplifies access to service configuration properties in the
 * Cloud Foundry environment.
 */
public class CFConstants {
	public static final String VCAP_SERVICES = "VCAP_SERVICES";
	public static final String VCAP_APPLICATION = "VCAP_APPLICATION";
	public static final String CREDENTIALS = "credentials";
	public static final String SERVICE_PLAN = "plan";
	public static final String URL = "url";
	public static final String CLIENT_ID = "clientid";
	public static final String CLIENT_SECRET = "clientsecret";
	public static final String CERTIFICATE = "certificate";
	public static final String KEY = "key";
	
	/*
	 * Mind the difference between
	 * - binding_name
	 * - instance_name
	 * and 
	 * - name (which defaults to binding_name, if exists, or instance_name as fallback).
	 * For further details refer to section "VCAP_SERVICES" at https://docs.cloudfoundry.org/devguide/deploy-apps/environment-variable.html
	 */
	public static final String NAME = "name";

	private CFConstants() {
	}

	/**
	 * Constants that are specific to the Xsuaa identity service.
	 */
	public static class XSUAA {
		private XSUAA() {
		}

		public static final String IDENTITY_ZONE = "identityzone";
		public static final String API_URL = "apiurl";
		public static final String SUBACCOUNT_ID = "subaccountid";
		public static final String TENANT_ID = "tenantid";
		public static final String UAA_DOMAIN = "uaadomain";
		public static final String APP_ID = "xsappname";
		public static final String VERIFICATION_KEY = "verificationkey";
		public static final String CERT_URL = "certurl";
		public static final String CREDENTIAL_TYPE = "credential-type";

	}

	/**
	 * Constants that are specific to the Ias identity service.
	 */
	public static class IAS {
		private IAS() {
		}

		/**
		 * @deprecated in favor of {@link IAS#DOMAINS}
		 */
		public static final String DOMAIN = "domain";
		public static final String DOMAINS = "domains";
	}

	/**
	 * Represents the service plans on CF marketplace. The various plans are
	 * considered in {@code CFEnvironment#loadXsuaa()}
	 */
	public enum Plan {
		DEFAULT, BROKER, APPLICATION, SPACE, APIACCESS, SYSTEM;

		public static Plan from(String planAsString) {
			if (planAsString == null) {
				return APPLICATION;
			}
			return Plan.valueOf(planAsString.toUpperCase());
		}

		@Override
		public String toString() {
			return super.toString().toLowerCase();
		}
	}
}
