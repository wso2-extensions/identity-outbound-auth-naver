package org.wso2.carbon.identity.application.authenticator.social.naver;

import mockit.Delegate;
import mockit.Expectations;
import mockit.Mocked;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;

public class NaverAuthenticatorTests {

    private NaverCustomAuthenticator naverAuthenticator;

    @Mocked
    private OAuthClientRequest.TokenRequestBuilder mockTokenRequestBuilder;

    @BeforeMethod
    public void setUp() {

        naverAuthenticator = new NaverCustomAuthenticator();
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testTokenRequestException() throws Exception {

        new Expectations() {{
            mockTokenRequestBuilder.buildQueryMessage();
            result = new Delegate() {
                OAuthClientRequest buildQueryMessage() throws OAuthSystemException {

                    throw new OAuthSystemException();
                }
            };
        }};
        OAuthClientRequest oAuthClientRequest = naverAuthenticator.buidTokenRequest(TestConstants
                        .naverTokenEndpoint, TestConstants.dummyClientId, TestConstants.dummyClientSecret,
                TestConstants.callbackURL, TestConstants.dummyAuthCode);
    }

}

