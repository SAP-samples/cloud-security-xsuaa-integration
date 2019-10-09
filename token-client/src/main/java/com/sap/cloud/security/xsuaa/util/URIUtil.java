package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.xsuaa.Assertions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

public class URIUtil {

	private static final Logger logger = LoggerFactory.getLogger(URIUtil.class);

	/**
	 * Utility method that replaces the subdomain of the URI with the given
	 * subdomain.
	 *
	 * @param uri
	 *            the URI to be replaced.
	 * @param subdomain
	 *            of the tenant.
	 * @return the URI with the replaced subdomain or the passed URI in case a
	 *         replacement was not possible.
	 */
	public static URI replaceSubdomain(@Nonnull URI uri, @Nullable String subdomain) {
		Assertions.assertNotNull(uri, "the uri parameter must not be null");
		if (hasText(subdomain) && hasSubdomain(uri)) {
			String newHost = subdomain + uri.getHost().substring(uri.getHost().indexOf('.'));
			try {
				return uri.resolve(new URI(
						uri.getScheme(), uri.getUserInfo(), newHost,
						uri.getPort(), uri.getPath(), uri.getQuery(), uri.getFragment()

				));
			} catch (URISyntaxException e) {
				logger.error("Malformed uri {} or subdomain {}", uri, subdomain, e);
			}
		}
		logger.warn("the subdomain of the URI '{}' is not replaced by subdomain '{}'", uri, subdomain);
		return uri;
	}

	private static boolean hasSubdomain(URI uri) {
		return uri.getHost().contains(".");
	}

	private static boolean hasText(String string) {
		return Optional.ofNullable(string).filter(str -> !str.trim().isEmpty()).isPresent();
	}
}
