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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oauth2.Oauth2GenericAuthenticator;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/*
 * Naver Custom Authenticator is an outbound authenticator implementation for social login provider named Naver
 * This extends Oauth Generic Authenticator implementation
 */
public class NaverCustomAuthenticator extends Oauth2GenericAuthenticator {

    private static final Log logger = LogFactory.getLog(Oauth2GenericAuthenticator.class);

    private static final long serialVersionUID = 6614257960044886319L;

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
}
