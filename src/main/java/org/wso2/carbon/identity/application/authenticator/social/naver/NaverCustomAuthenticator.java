/*******************************************************************************
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 * 
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
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
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
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
		
		if (logger.isDebugEnabled()) {
			logger.debug("initiateAuthenticationRequest");
		}

		String stateToken = generateState();
		this.stateToken = stateToken;

		try {
			Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
			String clientId = authenticatorProperties.get(NaverCustomAuthenticatorConstants.CLIENT_ID);
			String authorizationEP = getAuthorizationServerEndpoint();
			String callbackUrl = authenticatorProperties.get(NaverCustomAuthenticatorConstants.CALLBACK_URL);
			context.setContextIdentifier(stateToken);
			String state = stateToken + "," + NaverCustomAuthenticatorConstants.NAVER_LOGIN_TYPE;
			
			OAuthClientRequest authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP)
					.setClientId(clientId).setResponseType("code").setRedirectURI(callbackUrl).setState(state)
					.buildQueryMessage();

			if (logger.isDebugEnabled()) {
				logger.debug("authzRequest");
				logger.debug(authzRequest.getLocationUri());
			}
			response.sendRedirect(authzRequest.getLocationUri());

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

		if (logger.isDebugEnabled()) {
			logger.debug("processAuthenticationResponse");
		}
		logger.trace("InNaverebookAuthenticator.authenticate()");

		try {
				Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
				String clientId = authenticatorProperties.get(NaverCustomAuthenticatorConstants.CLIENT_ID);
				String clientSecret = authenticatorProperties.get(NaverCustomAuthenticatorConstants.CLIENT_SECRET);
				String tokenEndPoint = getTokenEndpoint();

				String code = getAuthorizationCode(request);
				String token = getToken(tokenEndPoint, clientId, clientSecret, code);
				String nvauthUserInfoUrl = getUserInfoEndpoint();

				Map<String, String> requestHeaders = new HashMap<>();
				requestHeaders.put("Authorization", "Bearer " + token);
				String responseBody = getUserInfo(nvauthUserInfoUrl, requestHeaders);

				if (logger.isDebugEnabled()) {
					logger.debug("Get user info response : " + responseBody);
				}

				JSONObject userInfoJson = new JSONObject(responseBody);
				buildClaims(context, userInfoJson.optJSONObject("response"));

			
		} catch (ApplicationAuthenticatorException e) {
			logger.error("Failed to process Naver Connect response.", e);
			throw new AuthenticationFailedException(e.getMessage(), e);
		}

	}

	protected String getToken(String tokenEndPoint, String clientId, String clientSecret, String code)
			throws ApplicationAuthenticatorException {

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

	protected String getAuthorizationCode(HttpServletRequest request) throws ApplicationAuthenticatorException {
		OAuthAuthzResponse authzResponse;
		try {
			authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
			return authzResponse.getCode();
		} catch (OAuthProblemException e) {
			throw new ApplicationAuthenticatorException("Exception while reading authorization code.", e);
		}
	}

	protected String sendRequest(String url) throws IOException {
		BufferedReader bufferReader = null;
		StringBuilder stringBuilder = new StringBuilder();

		try {
			URLConnection urlConnection = new URL(url).openConnection();
			bufferReader = new BufferedReader(
					new InputStreamReader(urlConnection.getInputStream(), Charset.forName("utf-8")));

			String inputLine = bufferReader.readLine();
			while (inputLine != null) {
				stringBuilder.append(inputLine).append("\n");
				inputLine = bufferReader.readLine();
			}
		} finally {
			IdentityIOStreamUtils.closeReader(bufferReader);
		}

		return stringBuilder.toString();
	}

	protected OAuthClientRequest buidTokenRequest(String tokenEndPoint, String clientId, String clientSecret,
			String state, String code) throws ApplicationAuthenticatorException {
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

	@Override
	public boolean canHandle(HttpServletRequest request) {
		if (isOauthStateParamExists(request) && (isOauth2CodeParamExists(request))) {
			return true;
		}
		return false;
	}
	
	protected String getUserInfo(String apiUrl, Map<String, String> requestHeaders) {
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

	protected HttpURLConnection connect(String apiUrl) {
		try {
			URL url = new URL(apiUrl);
			return (HttpURLConnection) url.openConnection();
		} catch (MalformedURLException e) {
			throw new RuntimeException("API URL is Invalid. : " + apiUrl, e);
		} catch (IOException e) {
			throw new RuntimeException("Connection failed. : " + apiUrl, e);
		}
	}

	protected String readBody(InputStream body) {
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
	public String getContextIdentifier(HttpServletRequest request) {
		String state = null;
		try {
			state = OAuthAuthzResponse.oauthCodeAuthzResponse(request).getState();
			return state.split(",")[0];

		} catch (OAuthProblemException e1) {
			logger.error("No context");
			e1.printStackTrace();
		}
		return state;
	}
	
	protected boolean isOauth2CodeParamExists(HttpServletRequest request) {
		return request.getParameter(NaverCustomAuthenticatorConstants.NAVER_GRANT_TYPE_CODE) != null;
	}

	protected boolean isOauthStateParamExists(HttpServletRequest request) {
		return request.getParameter(NaverCustomAuthenticatorConstants.NAVER_PARAM_STATE) != null
				&& NaverCustomAuthenticatorConstants.NAVER_LOGIN_TYPE.equals(getLoginType(request));
	}

	protected String getLoginType(HttpServletRequest request) {
		String state = request.getParameter(NaverCustomAuthenticatorConstants.NAVER_PARAM_STATE);
		if (StringUtils.isNotBlank(state) && state.split(",").length > 1) {
			return state.split(",")[1];
		} else {
			return null;
		}
	}

	protected void buildClaims(AuthenticationContext context, JSONObject userInfoJson)
			throws ApplicationAuthenticatorException {

		Map<ClaimMapping, String> claims;

		if (userInfoJson != null) {
			String id = null, nickName = null, name = null, email = null, gender = null, age = null, birthDay = null,
					profileImage = null;

			if (userInfoJson.has(NaverCustomAuthenticatorConstants.NV_USER_ID))
				id = userInfoJson.getString(NaverCustomAuthenticatorConstants.NV_USER_ID);

			if (userInfoJson.has(NaverCustomAuthenticatorConstants.NV_USER_NICKNAME))
				nickName = userInfoJson.getString(NaverCustomAuthenticatorConstants.NV_USER_NICKNAME);

			if (userInfoJson.has(NaverCustomAuthenticatorConstants.NV_USER_NAME))
				name = userInfoJson.getString(NaverCustomAuthenticatorConstants.NV_USER_NAME);

			if (userInfoJson.has(NaverCustomAuthenticatorConstants.NV_USER_EMAIL))
				email = userInfoJson.getString(NaverCustomAuthenticatorConstants.NV_USER_EMAIL);

			if (userInfoJson.has(NaverCustomAuthenticatorConstants.NV_USER_GENDER))
				gender = userInfoJson.getString(NaverCustomAuthenticatorConstants.NV_USER_GENDER);

			if (userInfoJson.has(NaverCustomAuthenticatorConstants.NV_USER_AGE))
				age = userInfoJson.getString(NaverCustomAuthenticatorConstants.NV_USER_AGE);

			if (userInfoJson.has(NaverCustomAuthenticatorConstants.NV_USER_BDAY))
				birthDay = userInfoJson.getString(NaverCustomAuthenticatorConstants.NV_USER_BDAY);

			if (userInfoJson.has(NaverCustomAuthenticatorConstants.NV_USER_IMAGE))
				profileImage = userInfoJson.getString(NaverCustomAuthenticatorConstants.NV_USER_IMAGE);

			claims = new HashMap<ClaimMapping, String>();
			claims.put(ClaimMapping.build(NaverCustomAuthenticatorConstants.NV_USER_ID, NaverCustomAuthenticatorConstants.NV_USER_ID, null, false), id);
			claims.put(ClaimMapping.build(NaverCustomAuthenticatorConstants.NV_USER_NICKNAME, NaverCustomAuthenticatorConstants.NV_USER_NICKNAME, null, false), nickName);
			claims.put(ClaimMapping.build(NaverCustomAuthenticatorConstants.NV_USER_NAME, NaverCustomAuthenticatorConstants.NV_USER_NAME, null, false), name);
			claims.put(ClaimMapping.build(NaverCustomAuthenticatorConstants.NV_USER_EMAIL, NaverCustomAuthenticatorConstants.NV_USER_EMAIL, null, false), email);
			claims.put(ClaimMapping.build(NaverCustomAuthenticatorConstants.NV_USER_GENDER, NaverCustomAuthenticatorConstants.NV_USER_GENDER, null, false), gender);
			claims.put(ClaimMapping.build(NaverCustomAuthenticatorConstants.NV_USER_AGE, NaverCustomAuthenticatorConstants.NV_USER_AGE, null, false), age);
			claims.put(ClaimMapping.build(NaverCustomAuthenticatorConstants.NV_USER_BDAY, NaverCustomAuthenticatorConstants.NV_USER_BDAY, null, false), birthDay);
			claims.put(ClaimMapping.build(NaverCustomAuthenticatorConstants.NV_USER_IMAGE, NaverCustomAuthenticatorConstants.NV_USER_IMAGE, null, false), profileImage);

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

	protected String generateState() {
		SecureRandom random = new SecureRandom();
		return new BigInteger(130, random).toString(32);
	}

	@Override
	public String getFriendlyName() {
		return "NAVER";
	}

	@Override
	public String getName() {
		return NaverCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
		
	}

	@Override
	public List<Property> getConfigurationProperties() {
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

	protected String getAuthorizationServerEndpoint() {
		return "https://nid.naver.com/oauth2.0/authorize";
	}

	protected String getUserInfoEndpoint() {
		return "https://openapi.naver.com/v1/nid/me";
	}

	protected String getTokenEndpoint() {
		return "https://nid.naver.com/oauth2.0/token";
	}

}
