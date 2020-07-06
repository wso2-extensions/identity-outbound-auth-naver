/*******************************************************************************
 * Copyright 2015 WSO2 Inc. (http://wso2.org)
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   
 *  http://www.apache.org/licenses/LICENSE-2.0
 *   
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

package org.wso2.carbon.identity.application.authenticator.social.naver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;

public class NaverCustomAuthenticator extends AbstractApplicationAuthenticator
		implements FederatedApplicationAuthenticator {

	private static final long serialVersionUID = 8654763286341993633L;
	private static final Log logger = LogFactory.getLog(NaverCustomAuthenticator.class);

	private String stateToken;

	@Override
	protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
			AuthenticationContext context) throws AuthenticationFailedException {
		logger.info("initiateAuthenticationRequest");

		String stateToken = generateState();
		this.stateToken = stateToken;

		try {
			Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
			String clientId = authenticatorProperties.get(NaverCustomAuthenticatorConstants.CLIENT_ID);
			String authorizationEP = getAuthorizationServerEndpoint();
			String callbackUrl = authenticatorProperties.get(NaverCustomAuthenticatorConstants.CALLBACK_URL);

			context.setContextIdentifier(stateToken);

			OAuthClientRequest authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
					.setClientId(clientId).setResponseType("code").setRedirectURI(callbackUrl).setState(stateToken)
					.buildQueryMessage();

			logger.info("authzRequest");
			logger.info(authzRequest.getLocationUri());

			response.sendRedirect(authzRequest.getLocationUri());
			logger.info("success");
		} catch (IOException e) {
			logger.error("Exception while sending to the login page.", e);
			throw new AuthenticationFailedException(e.getMessage(), e);
		} catch (OAuthSystemException e) {
			logger.error("Exception while building authorization code request.", e);
			throw new AuthenticationFailedException(e.getMessage(), e);
		}
		return;
	}

	@Override
	protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationContext context) throws AuthenticationFailedException {

		logger.info("processAuthenticationResponse");
		logger.trace("InNaverebookAuthenticator.authenticate()");

		try {
			if (validateStatusToken(request)) {

				Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
				String clientId = authenticatorProperties.get(NaverCustomAuthenticatorConstants.CLIENT_ID);
				String clientSecret = authenticatorProperties.get(NaverCustomAuthenticatorConstants.CLIENT_SECRET);
				String tokenEndPoint = getTokenEndpoint();

				String code = getAuthorizationCode(request);
				String token = getToken(tokenEndPoint, clientId, clientSecret, code);
				String nvauthUserInfoUrl = getUserInfoEndpoint();

				logger.debug("code >>>>>>> " + code);
				logger.debug("token >>>>>>> " + token);

				Map<String, String> requestHeaders = new HashMap<>();
				requestHeaders.put("Authorization", "Bearer " + token);
				String responseBody = getUserInfo(nvauthUserInfoUrl, requestHeaders);
				logger.info(responseBody);

				JSONObject userInfoJson = new JSONObject(responseBody);
				buildClaims(context, userInfoJson.optJSONObject("response"));

			} else {
				logger.error("State token validation failed");
			}
		} catch (ApplicationAuthenticatorException e) {
			logger.error("Failed to process Naver Connect response.", e);
			throw new AuthenticationFailedException(e.getMessage(), e);
		}

	}

	private void buildClaims(AuthenticationContext context, JSONObject userInfoJson)
			throws ApplicationAuthenticatorException {
		
		Map<ClaimMapping, String> claims;

		if (userInfoJson != null) {
			String id = null, nickName = null, name = null, email = null, gender = null, age = null, birthDay = null,
					profileImage = null;
			
			if (userInfoJson.has("id"))
				id = userInfoJson.getString("id");

			if (userInfoJson.has("nickname"))
				nickName = userInfoJson.getString("nickname");

			if (userInfoJson.has("name"))
				name = userInfoJson.getString("name");

			if (userInfoJson.has("email"))
				email = userInfoJson.getString("email");

			if (userInfoJson.has("gender"))
				gender = userInfoJson.getString("gender");

			if (userInfoJson.has("age"))
				age = userInfoJson.getString("age");

			if (userInfoJson.has("birthday"))
				birthDay = userInfoJson.getString("birthday");

			if (userInfoJson.has("profile_image"))
				profileImage = userInfoJson.getString("profile_image");

			claims = new HashMap<ClaimMapping, String>();
			claims.put(ClaimMapping.build("id", "id", null, false), id);
			claims.put(ClaimMapping.build("nickname", "nickname", null, false), nickName);
			claims.put(ClaimMapping.build("name", "name", null, false), name);
			claims.put(ClaimMapping.build("email", "email", null, false), email);
			claims.put(ClaimMapping.build("gender", "gender", null, false), gender);
			claims.put(ClaimMapping.build("age", "age", null, false), age);
			claims.put(ClaimMapping.build("birthDay", "birthDay", null, false), birthDay);
			claims.put(ClaimMapping.build("profileImage", "profileImage", null, false), profileImage);

			String subjectFromClaims = FrameworkUtils
						.getFederatedSubjectFromClaims(context.getExternalIdP().getIdentityProvider(), claims);
			
				if (StringUtils.isNotBlank(subjectFromClaims)) {
					AuthenticatedUser authenticatedUser = AuthenticatedUser
							.createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
					context.setSubject(authenticatedUser);
				} else {
					if (!StringUtils.isEmpty(userInfoJson.getString("id"))) {
						AuthenticatedUser authenticatedUser = AuthenticatedUser
								.createFederateAuthenticatedUserFromSubjectIdentifier(id);
						context.setSubject(authenticatedUser);
					} else {
						throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
					}
				}
				context.getSubject().setUserAttributes(claims);
			

		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("Decoded json object is null");
			}
			throw new ApplicationAuthenticatorException("Decoded json object is null");
		}

	}

	private String getToken(String tokenEndPoint, String clientId, String clientSecret, String code)
			throws ApplicationAuthenticatorException {
		logger.info("getToken");
		OAuthClientRequest tokenRequest = null;
		String token = null;
		String tokenResponseStr = null;
		try {
			String state = this.stateToken;
			tokenRequest = buidTokenRequest(tokenEndPoint, clientId, clientSecret, state, code);
			tokenResponseStr = sendRequest(tokenRequest.getLocationUri());
			JSONObject tokenResponse = new JSONObject(tokenResponseStr);
			token = tokenResponse.getString("access_token");

			if (token.startsWith("{")) {
				throw new ApplicationAuthenticatorException("Received access token is invalid.");
			}
		} catch (MalformedURLException e) {
			if (logger.isDebugEnabled()) {
				logger.debug("URL : " + tokenRequest.getLocationUri());
			}
			throw new ApplicationAuthenticatorException("MalformedURLException while sending access token request.", e);
		} catch (IOException e) {
			throw new ApplicationAuthenticatorException("IOException while sending access token request.", e);
		}
		return token;
	}

	private String getAuthorizationCode(HttpServletRequest request) throws ApplicationAuthenticatorException {
		logger.info("getAuthorizationCode");
		OAuthAuthzResponse authzResponse;
		try {
			authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
			return authzResponse.getCode();
		} catch (OAuthProblemException e) {
			throw new ApplicationAuthenticatorException("Exception while reading authorization code.", e);
		}
	}

	private String sendRequest(String url) throws IOException {
		logger.info("sendRequest");
		BufferedReader in = null;
		StringBuilder b = new StringBuilder();

		try {
			URLConnection urlConnection = new URL(url).openConnection();
			in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream(), Charset.forName("utf-8")));

			String inputLine = in.readLine();
			while (inputLine != null) {
				b.append(inputLine).append("\n");
				inputLine = in.readLine();
			}
		} finally {
			IdentityIOStreamUtils.closeReader(in);
		}

		return b.toString();
	}

	private OAuthClientRequest buidTokenRequest(String tokenEndPoint, String clientId, String clientSecret,
			String state, String code) throws ApplicationAuthenticatorException {
		logger.info("buidTokenRequest");
		OAuthClientRequest tokenRequest = null;
		try {
			tokenRequest = OAuthClientRequest.tokenLocation(tokenEndPoint).setClientId(clientId)
					.setClientSecret(clientSecret).setGrantType(GrantType.AUTHORIZATION_CODE).setCode(code)
					.setParameter("state", state).buildQueryMessage();
		} catch (OAuthSystemException e) {
			throw new ApplicationAuthenticatorException("Exception while building access token request.", e);
		}
		return tokenRequest;
	}

	private boolean validateStatusToken(HttpServletRequest request) throws ApplicationAuthenticatorException {
		OAuthAuthzResponse authzResponse;
		try {
			authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
			String receivedStateCode = authzResponse.getState();
			String sentStateCode = this.stateToken;
			if (receivedStateCode.equals(sentStateCode)) {
				return true;
			}
			return false;
		} catch (OAuthProblemException e) {
			throw new ApplicationAuthenticatorException("Exception while reading authorization status.", e);
		}
	}

	@Override
	public List<Property> getConfigurationProperties() {
		logger.info("getConfigurationProperties");
		List<Property> configProperties = new ArrayList<Property>();

		Property clientId = new Property();
		clientId.setName(NaverCustomAuthenticatorConstants.CLIENT_ID);
		clientId.setDisplayName("Client Id");
		clientId.setRequired(true);
		clientId.setDescription("Enter Naver client identifier value");
		configProperties.add(clientId);

		Property clientSecret = new Property();
		clientSecret.setName(NaverCustomAuthenticatorConstants.CLIENT_SECRET);
		clientSecret.setDisplayName("Client Secret");
		clientSecret.setRequired(true);
		clientSecret.setConfidential(true);
		clientSecret.setDescription("Enter Naver client secret value");
		configProperties.add(clientSecret);

		Property callbackUrl = new Property();
		callbackUrl.setName(NaverCustomAuthenticatorConstants.CALLBACK_URL);
		callbackUrl.setDisplayName("Callback Url");
		callbackUrl.setDescription("Enter Naver callback url");
		callbackUrl.setDefaultValue("id");
		callbackUrl.setRequired(false);
		configProperties.add(callbackUrl);

		return configProperties;
	}

	private static String getUserInfo(String apiUrl, Map<String, String> requestHeaders) {
		logger.debug("inside get user info");
		HttpURLConnection con = connect(apiUrl);
		try {
			con.setRequestMethod("GET");
			for (Map.Entry<String, String> header : requestHeaders.entrySet()) {
				con.setRequestProperty(header.getKey(), header.getValue());
			}

			int responseCode = con.getResponseCode();
			if (responseCode == HttpURLConnection.HTTP_OK) {
				return readBody(con.getInputStream());
			} else {
				return readBody(con.getErrorStream());
			}
		} catch (IOException e) {
			throw new RuntimeException("API Invoke failed", e);
		} finally {
			con.disconnect();
		}
	}

	private static HttpURLConnection connect(String apiUrl) {
		try {
			URL url = new URL(apiUrl);
			return (HttpURLConnection) url.openConnection();
		} catch (MalformedURLException e) {
			throw new RuntimeException("API URL is Invalid. : " + apiUrl, e);
		} catch (IOException e) {
			throw new RuntimeException("Connection failed. : " + apiUrl, e);
		}
	}

	private static String readBody(InputStream body) {
		logger.debug("inside readbody");
		InputStreamReader streamReader = new InputStreamReader(body);

		try (BufferedReader lineReader = new BufferedReader(streamReader)) {
			StringBuilder responseBody = new StringBuilder();

			String line;
			while ((line = lineReader.readLine()) != null) {
				responseBody.append(line);
			}

			return responseBody.toString();
		} catch (IOException e) {
			throw new RuntimeException("API Failed to read response.", e);
		}
	}

	@Override
	public boolean canHandle(HttpServletRequest request) {
		logger.debug("inside canHandle");
		if (request.getParameter(NaverCustomAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE) != null) {
			return true;
		}
		return false;
	}
	
	@Override
	public String getContextIdentifier(HttpServletRequest request) {
		logger.debug("inside getContextIdentifier");
		OAuthAuthzResponse authzResponse;
		try {
			authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
			String receivedStateCode = authzResponse.getState();
			return receivedStateCode;
		} catch (OAuthProblemException e) {
			logger.error("No context");
			e.printStackTrace();
			return null;
		}
	}
	
	public String generateState() {
		SecureRandom random = new SecureRandom();
		return new BigInteger(130, random).toString(32);
	}

	@Override
	public String getFriendlyName() {
		logger.debug("inside getFriendlyName");
		return "NAVER";
	}

	@Override
	public String getName() {
		logger.debug("inside getName");
		return "NAVER";
	}

	private String getAuthorizationServerEndpoint() {
		return "https://nid.naver.com/oauth2.0/authorize";
	}
	
	private String getUserInfoEndpoint() {
		return "https://openapi.naver.com/v1/nid/me";
	}

	private String getTokenEndpoint() {
		return "https://nid.naver.com/oauth2.0/token";
	}

}
