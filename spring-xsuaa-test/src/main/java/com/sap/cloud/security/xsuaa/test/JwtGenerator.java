package com.sap.cloud.security.xsuaa.test;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;

import org.apache.commons.io.IOUtils;
import org.springframework.lang.Nullable;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;

/**
 * Create tokens with a fixed private/public key and dummy values. The client
 * ID, identity zone, and scopes are configurable.
 */
public class JwtGenerator {

	public static final Date NO_EXPIRE_DATE = new GregorianCalendar(2190, 12, 31).getTime();
	public static final int NO_EXPIRE = Integer.MAX_VALUE;
	public static final String CLIENT_ID = "sb-xsapplication!t895";
	public static final String AUD = "xsapplication";
	// must be 'uaa' to make use of mockserver (see
	// XsuaaServiceConfigurationDefault.getTokenKeyUrl)
	public static final String IDENTITY_ZONE_ID = "uaa";
	private static final String PRIVATE_KEY_FILE = "/privateKey.txt";
	private final String clientId;
	private final String identityZone;
	// see TokenImpl.GRANTTYPE_SAML2BEARER;
	private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer";
	private String[] scopes;
	private String userName = "testuser";
	private String jwtHeaderKeyId;
	public Map<String, List<String>> attributes = new HashMap<>();
	private Map<String, Object> customClaims = new LinkedHashMap();
	private boolean deriveAudiences = false;

	/**
	 * @param clientId
	 *            the client ID that will be used for any created token
	 */
	public JwtGenerator(String clientId) {
		this.clientId = clientId;
		this.identityZone = IDENTITY_ZONE_ID;
	}

	public JwtGenerator() {
		this(CLIENT_ID);
	}

	/**
	 * Changes the value of the jwt claim "user_name". The user name is also used
	 * for the "email" claim.
	 *
	 * @param userName
	 *            the user name
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator setUserName(String userName) {
		this.userName = userName;
		return this;
	}

	/**
	 * Sets the roles as claim "scope" to the jwt.
	 *
	 * @param scopes
	 *            the scopes that should be part of the token
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator addScopes(String... scopes) {
		this.scopes = scopes;
		return this;
	}

	/**
	 * Adds the attributes as claim "xs.user.attribute" to the jwt.
	 *
	 * @param attributeName
	 *            the attribute name that should be part of the token
	 * @param attributeValues
	 *            the attribute value that should be part of the token
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator addAttribute(String attributeName, String[] attributeValues) {
		List<String> valueList = new ArrayList<>(Arrays.asList(attributeValues));
		attributes.put(attributeName, valueList);
		return this;
	}

	/**
	 * Sets the keyId value as "kid" header to the jwt.
	 *
	 * @param keyId
	 *            the value of the signed jwt token header "kid"
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator setJwtHeaderKeyId(String keyId) {
		this.jwtHeaderKeyId = keyId;
		return this;
	}

	/**
	 * Adds additional custom claims.
	 *
	 * @param customClaims
	 *            the claims that should be part of the token
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator addCustomClaims(Map<String, Object> customClaims) {
		this.customClaims.putAll(customClaims);
		return this;
	}

	/**
	 * Derives audiences claim ("aud") from scopes. For example in case e.g.
	 * "xsappid.scope".
	 *
	 * @param shallDeriveAudiences
	 *            if true, audiences are automatically set
	 * @return the JwtGenerator itself
	 */
	public JwtGenerator deriveAudiences(boolean shallDeriveAudiences) {
		this.deriveAudiences = shallDeriveAudiences;
		return this;
	}

	/**
	 * Returns an encoded JWT token for the "Authorization" REST header
	 *
	 * @return jwt token String with "Bearer " prefix
	 */
	public String getTokenForAuthorizationHeader() {
		try {
			return "Bearer " + getToken().getTokenValue();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Builds a basic Jwt with the given clientId, userName, scopes, user attributes
	 * claims and the keyId header.
	 *
	 * @return jwt
	 */
	public Jwt getToken() {
		JWTClaimsSet.Builder claimsSetBuilder = getBasicClaimSet();

		if (scopes != null && scopes.length > 0) {
			claimsSetBuilder.claim("scope", scopes);
			if (deriveAudiences) {
				claimsSetBuilder.audience(deriveAudiencesFromScopes(scopes));
			}
		}
		if (attributes.size() > 0) {
			claimsSetBuilder.claim("xs.user.attributes", attributes);
		}
		for (Map.Entry<String, Object> customClaim : customClaims.entrySet()) {
			claimsSetBuilder.claim(customClaim.getKey(), customClaim.getValue());
		}

		return createFromClaims(claimsSetBuilder.build().toString(), jwtHeaderKeyId);
	}

	private List<String> deriveAudiencesFromScopes(String[] scopes) {
		List<String> audiences = new ArrayList<>();
		for (String scope : scopes) {
			if (scope.contains(".")) {
				String aud = scope.substring(0, scope.indexOf("."));
				if (!audiences.contains(aud)) {
					audiences.add(aud);
				}
			}
		}
		return audiences;
	}

	/**
	 * Creates a Jwt from a template file, which contains the claims. Optionally,
	 * configure the "keyId" header via {@link #setJwtHeaderKeyId(String)}
	 * <p>
	 * This replaces these placeholders - "$exp" with a date, that will not expire -
	 * "$clientid" with the configured client id {@link #JwtGenerator(String)} -
	 * "$zid" with "uaa" - "$username" with the configured user name
	 * {@link #setUserName(String)}
	 *
	 * @param pathToTemplate
	 *            classpath resource
	 * @return a jwt
	 * @throws IOException
	 *             in case the template file can not be read
	 */
	public Jwt createFromTemplate(String pathToTemplate) throws IOException {
		String claimsFromTemplate = IOUtils.resourceToString(pathToTemplate, StandardCharsets.UTF_8);
		String claimsWithReplacements = replacePlaceholders(claimsFromTemplate);
		return createFromClaims(claimsWithReplacements, jwtHeaderKeyId);
	}

	/**
	 * Creates a Jwt from a file, which contains an encoded Jwt token.
	 *
	 * @param pathToJwt
	 *            classpath resource
	 * @return a jwt
	 * @throws IOException
	 *             in case the template file can not be read
	 */
	public static Jwt createFromFile(String pathToJwt) throws IOException {
		return convertTokenToOAuthJwt(IOUtils.resourceToString(pathToJwt, Charset.forName("UTF-8")));
	}

	/**
	 * Creates an individual Jwt based on the provided set of claims.
	 *
	 * @param claimsSet
	 *            that can be created with Nimbus JOSE + JWT JWTClaimsSet.Builder
	 * @return a jwt
	 */
	public static Jwt createFromClaims(JWTClaimsSet claimsSet) {
		return createFromClaims(claimsSet.toString(), null);
	}

	/**
	 * Builds a basic set of claims
	 *
	 * @return a basic set of claims
	 */
	private JWTClaimsSet.Builder getBasicClaimSet() {
		return new JWTClaimsSet.Builder()
				.issueTime(new Date())
				.expirationTime(JwtGenerator.NO_EXPIRE_DATE)
				.claim("client_id", clientId)
				.claim("origin", "userIdp")
				.claim("cid", clientId)
				.claim("user_name", userName)
				.claim("user_id", "D012345")
				.claim("email", userName + "@test.org")
				.claim("zid", identityZone)
				.claim("grant_type", GRANT_TYPE);
	}

	private static Jwt createFromClaims(String claims, String jwtHeaderKeyId) {
		String token = signAndEncodeToken(claims, jwtHeaderKeyId);
		return convertTokenToOAuthJwt(token);
	}

	private String replacePlaceholders(String claims) {
		claims = claims.replace("$exp", String.valueOf(NO_EXPIRE));
		claims = claims.replace("$clientid", clientId);
		claims = claims.replace("$zid", identityZone);
		claims = claims.replace("$username", userName);

		return claims;
	}

	private static String signAndEncodeToken(String claims, String keyId) {
		RsaSigner signer = new RsaSigner(readPrivateKeyFromFile());

		Map<String, String> headers = Collections.emptyMap();
		if (keyId != null) {
			headers = new HashMap<>();
			headers.put("kid", keyId);
		}

		org.springframework.security.jwt.Jwt jwt = JwtHelper.encode(claims, signer, headers);

		return jwt.getEncoded();
	}

	protected static String readPrivateKeyFromFile() {
		String privateKey;
		try {
			privateKey = IOUtils.resourceToString(PRIVATE_KEY_FILE, StandardCharsets.UTF_8); // PEM format
		} catch (IOException e) {
			throw new RuntimeException("privateKey could not be read from " + PRIVATE_KEY_FILE, e);
		}
		return privateKey;
	}

	@Nullable
	public static Jwt convertTokenToOAuthJwt(String token) {
		Jwt jwt;
		try {
			JWT parsedJwt = JWTParser.parse(token);
			JWTClaimsSet jwtClaimsSet = parsedJwt.getJWTClaimsSet();
			Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
			jwt = new Jwt(parsedJwt.getParsedString(), jwtClaimsSet.getIssueTime().toInstant(),
					jwtClaimsSet.getExpirationTime().toInstant(), headers, jwtClaimsSet.getClaims());
		} catch (ParseException e) {
			throw new IllegalArgumentException("token can not be parsed. ", e);
		}
		return jwt;
	}
}