package org.wso2.carbon.identity.application.authenticator.social.naver;

import mockit.Deencapsulation;
import mockit.Delegate;
import mockit.Expectations;
import mockit.Mocked;
import mockit.Tested;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class NaverAuthenticatorTests {

    private NaverCustomAuthenticator naverAuthenticator;

    @Mocked
    private HttpServletRequest mockHttpServletRequest;
    @Mocked
    private HttpServletResponse mockHttpServletResponse;
    @Mocked
    private AuthenticationContext mockAuthenticationContext;
    @Tested
    private NaverCustomAuthenticator mockNVAuthenticator;
    @Mocked
    private IdentityUtil mockIdentityUtil;
    @Mocked
    private OAuthClientRequest.TokenRequestBuilder mockTokenRequestBuilder;

    @BeforeMethod
    public void setUp() throws Exception {

        naverAuthenticator = new NaverCustomAuthenticator();
    }

}

