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

//    @Test
//    public void testInvalidTokenRequest() throws Exception {
//
//        new Expectations() {
//            { /* define in static block */
//                mockHttpServletRequest.getParameter("state");
//                returns(TestConstants.dummyCommonAuthId, null);
//            }
//        };
//        Assert.assertEquals(naverAuthenticator.getContextIdentifier(mockHttpServletRequest), TestConstants
//                .dummyCommonAuthId);
//        Assert.assertNull(naverAuthenticator.getContextIdentifier(mockHttpServletRequest));
//    }
//
//    @Test
//    public void testCanHandle() throws Exception {
//
//        new Expectations() {
//            { /* define in static block */
//                mockHttpServletRequest.getParameter(NaverCustomAuthenticatorConstants.NAVER_PARAM_STATE);
//                result =
//                        (TestConstants.dummyCommonAuthId + ",naver");
//                mockHttpServletRequest.getParameter(NaverCustomAuthenticatorConstants.NAVER_GRANT_TYPE_CODE);
//                result = ("Authorization");
//            }
//        };
//        Assert.assertEquals(naverAuthenticator.canHandle(mockHttpServletRequest), true);
//    }
//
//    @Test
//    public void canHandleFalse() throws Exception {
//
//        new Expectations() {
//            { /* define in static block */
//                mockHttpServletRequest.getParameter(NaverCustomAuthenticatorConstants.NAVER_PARAM_STATE);
//                result = null;
//            }
//        };
//        Assert.assertEquals(naverAuthenticator.canHandle(mockHttpServletRequest), false);
//
//        new Expectations() {
//            { /* define in static block */
//                mockHttpServletRequest.getParameter(NaverCustomAuthenticatorConstants.NAVER_PARAM_STATE);
//                result = TestConstants.dummyCommonAuthId + ",nothing";
//            }
//        };
//        Assert.assertEquals(naverAuthenticator.canHandle(mockHttpServletRequest), false);
//        new Expectations() {
//            { /* define in static block */
//                mockHttpServletRequest.getParameter(NaverCustomAuthenticatorConstants.NAVER_PARAM_STATE);
//                result = TestConstants.dummyCommonAuthId + ",naver";
//                mockHttpServletRequest.getParameter(NaverCustomAuthenticatorConstants.NAVER_GRANT_TYPE_CODE);
//                result = null;
//            }
//        };
//        Assert.assertEquals(naverAuthenticator.canHandle(mockHttpServletRequest), false);
//    }
//
//    @Test(expectedExceptions = IOException.class)
//    public void testSendRequestError() throws Exception {
//
//        naverAuthenticator.sendRequest(TestConstants.naverTokenEndpoint);
//    }
//
//    @Test
//    public void testSendRequest() throws Exception {
//
//        Assert.assertNotNull(naverAuthenticator.sendRequest("https://google.com"), "An error occured while doing " +
//                "redirection");
//    }
//
//
//    @Test
//    public void testAuthenticatorNames() {
//        Assert.assertEquals(naverAuthenticator.getName(), NaverCustomAuthenticatorConstants.AUTHENTICATOR_NAME, "Naver " +
//                "Authenticator did not return expected name");
//        Assert.assertEquals(naverAuthenticator.getFriendlyName(), "NAVER", "Naver authenticator did not return " +
//                "expected friendly name");
//    }
//
//    @Test
//    public void testGetLoginTypeWithNull() throws Exception {
//        new Expectations() {
//            {
//                mockHttpServletRequest.getParameter("state");
//                result = null;
//            }
//        };
//        Assert.assertNull(naverAuthenticator.getLoginType(mockHttpServletRequest), "getLoginType returned an " +
//                "unexpected result");
//    }
//
//    @Test
//    public void testInitiateAuthRequest() throws Exception {
//
//        final String[] redirectedUrl = new String[1];
//        buildExpectationsForInitiateReq(TestConstants.customNaverEndpoint, "profile", TestConstants.callbackURL);
//        new Expectations() {{
//            mockHttpServletResponse.sendRedirect(anyString);
//            result = new Delegate() {
//                void sendRedirect(String redirectURL) {
//                    redirectedUrl[0] = redirectURL;
//                }
//            };
//        }};
//        mockNVAuthenticator.initiateAuthenticationRequest(mockHttpServletRequest, mockHttpServletResponse,
//                mockAuthenticationContext);
//
//        Assert.assertTrue(redirectedUrl[0].contains("scope=profile"), "Scope is not present in redirect url");
//        Assert.assertTrue(redirectedUrl[0].contains("response_type=code"), "Response type is not present in redirect " +
//                "url");
//        Assert.assertTrue(redirectedUrl[0].contains("client_id=" + TestConstants.dummyClientId), "Client ID is not " +
//                "present in redirect url");
//        Assert.assertTrue(redirectedUrl[0].contains("state=" + TestConstants.dummyCommonAuthId + "%2Cnaver"),
//                "State parameter is not present in redirect url");
//    }
//
//    @Test(expectedExceptions = AuthenticationFailedException.class)
//    public void testInitAuthReqWithOAuthSystemException() throws Exception {
//
//        buildExpectationsForInitiateReq(TestConstants.customNaverEndpoint, "profile", TestConstants.callbackURL);
//        new Expectations() {{
//            mockHttpServletResponse.sendRedirect(anyString);
//            result = new Delegate() {
//                void sendRedirect(String redirectURL) throws OAuthSystemException {
//                    throw new OAuthSystemException("Error while doing IO operation");
//                }
//            };
//        }};
//        mockNVAuthenticator.initiateAuthenticationRequest(mockHttpServletRequest, mockHttpServletResponse,
//                mockAuthenticationContext);
//    }
//
//    @Test(expectedExceptions = AuthenticationFailedException.class)
//    public void testInitiateAuthReqWithIOException() throws Exception {
//
//        buildExpectationsForInitiateReq(TestConstants.customNaverEndpoint, "profile", TestConstants.callbackURL);
//        new Expectations() {{
//            mockHttpServletResponse.sendRedirect(anyString);
//            result = new Delegate() {
//                void sendRedirect(String redirectURL) throws IOException {
//                    throw new IOException("Error while doing IO operation");
//                }
//            };
//        }};
//        mockNVAuthenticator.initiateAuthenticationRequest(mockHttpServletRequest, mockHttpServletResponse,
//                mockAuthenticationContext);
//    }
//
//    @Test
//    public void testInitiateAuthReqWithDefaultConfigs() throws Exception {
//
//        final String[] redirectedUrl = new String[1];
//        final String customHost = "https://somehost:9443/commonauth";
//        new Expectations() {
//            { /* define in static block */
//                mockIdentityUtil.getServerURL(anyString, anyBoolean, anyBoolean);
//                result = customHost;
//            }
//        };
//        buildExpectationsForInitiateReq(null, null, null);
//        new Expectations() {{
//            mockHttpServletResponse.sendRedirect(anyString);
//            result = new Delegate() {
//                void sendRedirect(String redirectURL) {
//                    redirectedUrl[0] = redirectURL;
//                }
//            };
//        }};
//        mockNVAuthenticator.initiateAuthenticationRequest(mockHttpServletRequest, mockHttpServletResponse,
//                mockAuthenticationContext);
//        Assert.assertTrue(redirectedUrl[0].contains("scope=email"), "Scope is not present in redirection url");
//        Assert.assertTrue(redirectedUrl[0].contains("response_type=code"), "Response type is not present in redirect " +
//                "url");
//        Assert.assertTrue(redirectedUrl[0].contains("client_id=" + TestConstants.dummyClientId), "Client ID is not " +
//                "present in redirect url");
//        Assert.assertTrue(redirectedUrl[0].contains("state=" + TestConstants.dummyCommonAuthId + "%2Cnaver"),
//                "State parameter is not present in redirect url");
//    }
//
//    private void buildExpectationsForInitiateReq(final String nvURL, final String scope, final String callbackURL) {
//
//        new Expectations(mockNVAuthenticator) {{
//            Deencapsulation.invoke(mockNVAuthenticator, "getAuthenticatorConfig");
//            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
//            Map parameters = new HashMap();
//            authenticatorConfig.setParameterMap(parameters);
//            result = authenticatorConfig;
//        }};
//
//        new Expectations() {
//            { /* define in static block */
//                Map parameters = new HashMap();
//                parameters.put(NaverCustomAuthenticatorConstants.CLIENT_ID, TestConstants.dummyClientId);
//                parameters.put(NaverCustomAuthenticatorConstants.CLIENT_ID, TestConstants.dummyClientId);
//                mockAuthenticationContext.getAuthenticatorProperties();
//                result = parameters;
//            }
//        };
//
//        new Expectations() {
//            { /* define in static block */
//                mockAuthenticationContext.getContextIdentifier();
//                result = TestConstants.dummyCommonAuthId;
//            }
//        };
//    }
}

