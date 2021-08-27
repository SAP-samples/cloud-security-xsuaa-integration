/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.mtls;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Collection;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

/**
 * Creates a SSLContext (without Bouncy Castle crypto lib).
 *
 */
public class SSLContextFactory {
	private static final char[] noPassword = "".toCharArray();
	private static final SSLContextFactory instance = new SSLContextFactory();
	private final Logger logger;

	private SSLContextFactory() {
		logger = LoggerFactory.getLogger(getClass());
	}

	public static SSLContextFactory getInstance() {
		return instance;
	}

	/**
	 * Creates a SSLContext which can be used to parameterize your Rest client, in
	 * order to support mutual TLS.
	 *
	 * @param x509Certificates
	 *            you can get from your Service Configuration {@link OAuth2ServiceConfiguration#getClientIdentity()}
	 * @param rsaPrivateKey
	 *            you can get from your Service Configuration{@link OAuth2ServiceConfiguration#getClientIdentity()}
	 * @return a new SSLContext instance
	 * @throws GeneralSecurityException
	 *             in case of key parsing errors
	 * @throws IOException
	 *             in case of KeyStore initialization errors
	 */
	public SSLContext create(String x509Certificates, String rsaPrivateKey)
			throws GeneralSecurityException, IOException {
		assertHasText(x509Certificates, "x509Certificate is required");
		assertHasText(rsaPrivateKey, "rsaPrivateKey is required");

		return create(new ClientCertificate(x509Certificates, rsaPrivateKey, null));
	}

	/**
	 * Creates a SSLContext which can be used to parameterize your Rest client, in
	 * order to support mutual TLS.
	 *
	 * @param clientIdentity
	 *            you can get from your Service Configuration {@link OAuth2ServiceConfiguration#getClientIdentity()}
	 * @return a new SSLContext instance
	 * @throws GeneralSecurityException
	 *             in case of key parsing errors
	 * @throws IOException
	 *             in case of KeyStore initialization errors
	 */
	public SSLContext create(ClientIdentity clientIdentity) throws GeneralSecurityException, IOException {
		assertNotNull(clientIdentity, "clientIdentity must not be null");
		assertHasText(clientIdentity.getCertificate(), "clientIdentity.getCertificate() must not return null");
		assertHasText(clientIdentity.getKey(), "clientIdentity.getKey() must not return null");

		KeyStore keystore = createKeyStore(clientIdentity);
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		keyManagerFactory.init(keystore, noPassword);
		SSLContext sslContext = createDefaultSSLContext();
		sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
		return sslContext;
	}

	/**
	 * Initializes a KeyStore which can be used to parameterize your Rest client, in
	 * order to support mutual TLS.
	 *
	 * @param clientIdentity
	 *            you can get from your Service Configuration {@link OAuth2ServiceConfiguration#getClientIdentity()}
	 * @return a new KeyStore instance
	 * @throws GeneralSecurityException
	 *             in case of key parsing errors
	 * @throws IOException
	 *             in case of KeyStore initialization errors
	 */
	public KeyStore createKeyStore(ClientIdentity clientIdentity) throws GeneralSecurityException, IOException {
		assertNotNull(clientIdentity, "clientIdentity must not be null");
		assertHasText(clientIdentity.getCertificate(), "clientIdentity.getCertificate() must not return null");
		assertHasText(clientIdentity.getKey(), "clientIdentity.getKey() must not return null");

		PrivateKey privateKey = getPrivateKeyFromString(clientIdentity.getKey());
		Certificate[] certificateChain = getCertificatesFromString(clientIdentity.getCertificate());

		return initializeKeyStore(privateKey, certificateChain);
	}

	private KeyStore initializeKeyStore(PrivateKey privateKey, Certificate[] certificateChain)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		KeyStore keystore = KeyStore.getInstance("jks");
		keystore.load(null); // there is no data in the keystore file - loads empty keystore
		int i = 0;
		for (Certificate certificate : certificateChain) {
			keystore.setCertificateEntry("cert-alias-" + "" + i++, certificate);
		}
		keystore.setKeyEntry("key-alias", privateKey, noPassword, certificateChain);

		return keystore;
	}

	private SSLContext createDefaultSSLContext() throws NoSuchAlgorithmException {
		return SSLContext.getInstance("TLS");
	}

	private PrivateKey getPrivateKeyFromString(final String rsaPrivateKey) throws GeneralSecurityException {
		String privateKeyPEM = rsaPrivateKey;
		privateKeyPEM = privateKeyPEM.replace("-----BEGIN RSA PRIVATE KEY-----", "");
		privateKeyPEM = privateKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
		privateKeyPEM = privateKeyPEM.replace("\n", "");
		privateKeyPEM = privateKeyPEM.replace("\\n", "");
		logger.debug("privateKeyPem: '{}'", privateKeyPEM);

		KeySpec keySpec = parseDERPrivateKey(Base64.getDecoder().decode(privateKeyPEM));

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}

	private Certificate[] getCertificatesFromString(String certificates) throws CertificateException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		byte[] certificatesBytes = certificates.replace("\\n", "\n").getBytes();

		Collection<Certificate> certificateList = (Collection<Certificate>) factory
				.generateCertificates(new ByteArrayInputStream(certificatesBytes));
		return certificateList.toArray(new Certificate[0]);
	}

	private KeySpec parseDERPrivateKey(byte[] privateKeyDerEncoded)
			throws GeneralSecurityException {
		KeySpec keySpec;
		MinimalDERParser parser = new MinimalDERParser(privateKeyDerEncoded);

		try {
			parser.getSequence();

			BigInteger version = parser.getBigInteger();
			if (!version.equals(BigInteger.ZERO)) {
				throw new IllegalArgumentException("Only version 0 supported for PKCS1 decoding.");
			}
			BigInteger modulus = parser.getBigInteger();
			BigInteger publicExponent = parser.getBigInteger();
			BigInteger privateExponent = parser.getBigInteger();
			BigInteger primeP = parser.getBigInteger();
			BigInteger primeQ = parser.getBigInteger();
			BigInteger primeExponentP = parser.getBigInteger();
			BigInteger primeExponentQ = parser.getBigInteger();
			BigInteger crtCoefficient = parser.getBigInteger();

			keySpec = new RSAPrivateCrtKeySpec(
					modulus,
					publicExponent,
					privateExponent,
					primeP,
					primeQ,
					primeExponentP,
					primeExponentQ,
					crtCoefficient);
		} catch (IOException e) {
			throw new GeneralSecurityException("Exception during parsing DER encoded private key", e);
		}
		return keySpec;
	}
}
