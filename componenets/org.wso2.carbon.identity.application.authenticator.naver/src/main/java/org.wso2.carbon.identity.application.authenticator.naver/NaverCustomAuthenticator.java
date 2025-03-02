/*
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
 */

package org.wso2.carbon.identity.application.authenticator.naver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.MisconfigurationException;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCTokenValidationUtil;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.util.IdPManagementConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.application.authenticator.naver.NaverCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.naver.NaverCustomAuthenticatorConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.application.authenticator.naver.NaverCustomAuthenticatorConstants.CALLBACK_URL;
import static org.wso2.carbon.identity.application.authenticator.naver.NaverCustomAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.naver.NaverCustomAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.naver.NaverCustomAuthenticatorConstants.IS_BASIC_AUTH_ENABLED;
import static org.wso2.carbon.identity.application.authenticator.naver.NaverCustomAuthenticatorConstants.ID_TOKEN_PARAM;
import static org.wso2.carbon.identity.application.authenticator.naver.NaverCustomAuthenticatorConstants.REDIRECT_URL_SUFFIX;


/*
 * Naver Custom Authenticator is an outbound authenticator implementation for social login provider named Naver
 * This extends Oauth Generic Authenticator implementation
 */
public class NaverCustomAuthenticator extends Oauth2GenericAuthenticator {

    private static final Log logger = LogFactory.getLog(Oauth2GenericAuthenticator.class);

    private static final long serialVersionUID = 6614257960044886319L;

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return isNativeSDKBasedFederationCall(request) || super.canHandle(request);
    }

    /**
     * Check whether the authentication is based on API.
     *
     * @return true since API based authentication is supported.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }

    /**
     * Get the i18n key defined to represent the authenticator name.
     *
     * @return the 118n key.
     */
    @Override
    public String getI18nKey() {

        return NaverCustomAuthenticatorConstants.AUTHENTICATOR_I18N_KEY;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        if (logger.isDebugEnabled()) {
            logger.debug("initiateAuthenticationRequest");
        }

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = (String)authenticatorProperties.get(CLIENT_ID);
            String callbackUrl = (String)authenticatorProperties.get(CALLBACK_URL);
            String authorizationEP = this.getAuthorizationServerEndpoint(authenticatorProperties);
            String state = context.getContextIdentifier() + "," + NaverCustomAuthenticatorConstants.OAUTH2;
            OAuthClientRequest authzRequest = OAuthClientRequest.authorizationLocation(authorizationEP).setClientId(clientId).setResponseType("code").setRedirectURI(callbackUrl).setState(state).buildQueryMessage();
            if (logger.isDebugEnabled()) {
                logger.debug("Authorization Request: " + authzRequest.getLocationUri());
            }

            context.setProperty(NaverCustomAuthenticatorConstants.OAUTH2_PARAM_STATE, state);
            context.setProperty(AUTHENTICATOR_NAME + NaverCustomAuthenticatorConstants.REDIRECT_URL_SUFFIX,
                    authzRequest.getLocationUri());
            response.sendRedirect(authzRequest.getLocationUri());
        } catch (IOException e) {
            logger.error("Exception while sending to the login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            logger.error("Exception while building authorization code request.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
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
    protected String getTokenEndpoint(Map<String, String> authenticatorProperties) {

        return NaverCustomAuthenticatorConstants.NV_TOKEN_URL;
    }

    @Override
    protected String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        return NaverCustomAuthenticatorConstants.NV_AUTH_URL;
    }

    @Override
    protected String getUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        return NaverCustomAuthenticatorConstants.NV_USER_INFO_URL;
    }

    @Override
    protected void buildClaims(AuthenticationContext context, String userInfoString)
            throws ApplicationAuthenticatorException {

        if (StringUtils.isNotBlank(userInfoString)) {
            JSONObject responseJson = new JSONObject(userInfoString);
            JSONObject userInfoJson = responseJson.getJSONObject("response");
            if (userInfoJson != null) {
                Map<ClaimMapping, String> claims = new HashMap<>();
                Iterator keys = userInfoJson.keys();
                while (keys.hasNext()) {
                    String key = (String) keys.next();
                    if (userInfoJson.get(key) instanceof JSONObject) {
                        claims.put(ClaimMapping.build(key, key, null, false),
                                (String) userInfoJson.get(key));
                    }
                }
                String subjectFromClaims = FrameworkUtils
                        .getFederatedSubjectFromClaims(context.getExternalIdP().getIdentityProvider(), claims);
                String id = null;
                if (userInfoJson.has(NaverCustomAuthenticatorConstants.NV_USER_ID)) {
                    id = userInfoJson.getString(NaverCustomAuthenticatorConstants.NV_USER_ID);
                }
                if (StringUtils.isNotBlank(subjectFromClaims)) {
                    AuthenticatedUser authenticatedUser = AuthenticatedUser
                            .createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
                    context.setSubject(authenticatedUser);
                } else {
                    if (StringUtils.isNotBlank(id)) {
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
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("Decoded json object is empty");
            }
            throw new ApplicationAuthenticatorException("Decoded json object is empty");
        }
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(NaverCustomAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter client identifier value");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(NaverCustomAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setConfidential(true);
        clientSecret.setDescription("Enter client secret value");
        clientSecret.setDisplayOrder(2);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setName(NaverCustomAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setRequired(true);
        callbackUrl.setDescription("Enter callback url");
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        return configProperties;
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     *         If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     *         an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setI18nKey(getI18nKey());
        String idpName = context.getExternalIdP().getIdPName();
        authenticatorData.setIdp(idpName);

        List<String> requiredParameterList = new ArrayList<>();
        if (isTrustedTokenIssuer(context)) {
            requiredParameterList.add(NaverCustomAuthenticatorConstants.ACCESS_TOKEN_PARAM);
            requiredParameterList.add(ID_TOKEN_PARAM);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, true));
        } else {
            requiredParameterList.add(NaverCustomAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE);
            requiredParameterList.add(NaverCustomAuthenticatorConstants.OAUTH2_PARAM_STATE);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, false));
        }
        authenticatorData.setRequiredParams(requiredParameterList);

        return Optional.of(authenticatorData);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        if (logger.isDebugEnabled()) {
            logger.debug("processAuthenticationResponse");
        }

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = (String)authenticatorProperties.get(CLIENT_ID);
            String clientSecret = (String)authenticatorProperties.get(CLIENT_SECRET);
            Boolean basicAuthEnabled = Boolean.parseBoolean((String)authenticatorProperties.get(IS_BASIC_AUTH_ENABLED));
            String tokenEP = this.getTokenEndpoint(authenticatorProperties);
            String token;
            if (isTrustedTokenIssuer(context) && isNativeSDKBasedFederationCall(request)) {
                String idToken = request.getParameter(ID_TOKEN_PARAM);
                token = request.getParameter(NaverCustomAuthenticatorConstants.ACCESS_TOKEN_PARAM);
                validateJWTToken(context, idToken);
            } else {
                String callbackUrl = getCallbackUrl(authenticatorProperties);
                if (Boolean.parseBoolean((String) context.getProperty(NaverCustomAuthenticatorConstants.IS_API_BASED))) {
                    callbackUrl = (String) context.getProperty(NaverCustomAuthenticatorConstants.REDIRECT_URL);
                }
                String code = getAuthorizationCode(request);
                token = getToken(tokenEP, clientId, clientSecret, code, callbackUrl, basicAuthEnabled);
            }

            Boolean selfContainedTokenEnabled = Boolean.parseBoolean(authenticatorProperties
                    .get(Oauth2GenericAuthenticatorConstants.SELF_CONTAINED_TOKEN_ENABLED));
            String userInfo = getUserInfo(selfContainedTokenEnabled, token, authenticatorProperties);

            this.buildClaims(context, userInfo);
        } catch (ApplicationAuthenticatorException | MisconfigurationException e) {
            logger.error("Failed to process Connect response.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (IdentityOAuth2Exception e) {
            throw new AuthenticationFailedException("JWT token is invalid.");
        } catch (ParseException | IdentityProviderManagementException | JOSEException e) {
            throw new AuthenticationFailedException("JWT token validation Failed.", e);
        }
    }

    private static AdditionalData getAdditionalData(
            AuthenticationContext context, boolean isNativeSDKBasedFederationCall) {

        AdditionalData additionalData = new AdditionalData();

        if (isNativeSDKBasedFederationCall) {
            Map<String, String> additionalAuthenticationParams = new HashMap<>();
            additionalAuthenticationParams.put(NaverCustomAuthenticatorConstants.CLIENT_ID_PARAM,
                    context.getAuthenticatorProperties().get(CLIENT_ID));
            additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);
        } else {
            Map<String, String> additionalAuthenticationParams = new HashMap<>();
            additionalData.setRedirectUrl((String) context.getProperty(
                    AUTHENTICATOR_NAME + REDIRECT_URL_SUFFIX));
            String state = (String) context.getProperty(OAUTH2_PARAM_STATE);
            additionalAuthenticationParams.put(OAUTH2_PARAM_STATE, state);
            additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);
        }
        return additionalData;
    }

    private boolean isTrustedTokenIssuer(AuthenticationContext context) {

        ExternalIdPConfig externalIdPConfig = context.getExternalIdP();
        if (externalIdPConfig == null) {
            return false;
        }

        IdentityProvider externalIdentityProvider = externalIdPConfig.getIdentityProvider();
        if (externalIdentityProvider == null) {
            return false;
        }

        IdentityProviderProperty[] identityProviderProperties = externalIdentityProvider.getIdpProperties();
        for (IdentityProviderProperty identityProviderProperty: identityProviderProperties) {
            if (IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER.equals(identityProviderProperty.getName())) {
                return Boolean.parseBoolean(identityProviderProperty.getValue());
            }
        }

        return false;
    }

    /**
     * Get the callback URL.
     *
     * @param authenticatorProperties Authenticator properties.
     * @return Callback URL.
     */
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        if (StringUtils.isNotEmpty(authenticatorProperties.get(CALLBACK_URL))) {
            return authenticatorProperties.get(CALLBACK_URL);
        }
        try {
            return ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new RuntimeException("Error occurred while building URL.", e);
        }
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

    private boolean isNativeSDKBasedFederationCall(HttpServletRequest request) {

        return request.getParameter(NaverCustomAuthenticatorConstants.ACCESS_TOKEN_PARAM) != null;
    }

    private void validateJWTToken(AuthenticationContext context, String idToken) throws
            ParseException, AuthenticationFailedException, JOSEException, IdentityOAuth2Exception, IdentityProviderManagementException {

        SignedJWT signedJWT = SignedJWT.parse(idToken);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        OIDCTokenValidationUtil.validateIssuerClaim(claimsSet);
        String tenantDomain = context.getTenantDomain();
        String idpIdentifier = OIDCTokenValidationUtil.getIssuer(claimsSet);
        IdentityProvider identityProvider = getIdentityProvider(idpIdentifier, tenantDomain);

        OIDCTokenValidationUtil.validateSignature(signedJWT, identityProvider);
        OIDCTokenValidationUtil.validateAudience(claimsSet.getAudience(), identityProvider, tenantDomain);
    }

    private IdentityProvider getIdentityProvider(String jwtIssuer, String tenantDomain)
            throws IdentityProviderManagementException {

        IdentityProvider identityProvider;
        identityProvider = IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                IdentityApplicationConstants.IDP_ISSUER_NAME, jwtIssuer, tenantDomain, false);

        if (identityProvider == null) {
            identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
        }

        return identityProvider;
    }
}
