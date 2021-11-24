/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * The X.509 certificate
 */
public class X509Certificate implements Certificate {

	private static final Logger LOGGER = LoggerFactory.getLogger(X509Certificate.class);

	private final java.security.cert.X509Certificate x509;
	private String thumbprint;

	private X509Certificate(java.security.cert.X509Certificate x509Certificate) {
		this.x509 = x509Certificate;
	}

	/**
	 * Creates a new instance of X.509 certificate.
	 *
	 * @param certificate
	 *            the certificate encoded in base64 or PEM format
	 * @return instance of X509certificate
	 */
	@Nullable
	public static X509Certificate newCertificate(String certificate) {
		if (certificate != null && !certificate.isEmpty()) {
			try {
				return new X509Certificate(X509Parser.parseCertificate(certificate));
			} catch (CertificateException e) {
				LOGGER.warn("Could not parse the certificate string", e);
			}
		}
		return null;
	}

	@Override
	public String getThumbprint() throws InvalidCertificateException {
		if (thumbprint == null) {
			try {
				this.thumbprint = X509Parser.getCertificateThumbprint(x509);
			} catch (NoSuchAlgorithmException | CertificateEncodingException e) {
				throw new InvalidCertificateException("Could not parse thumbprint", e);
			}
		}
		return this.thumbprint;
	}

}
