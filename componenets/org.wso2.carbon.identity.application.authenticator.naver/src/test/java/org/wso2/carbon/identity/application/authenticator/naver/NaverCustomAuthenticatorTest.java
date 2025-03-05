package org.wso2.carbon.identity.application.authenticator.naver;

import org.mockito.Mock;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeTest;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.doReturn;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.MockitoAnnotations.initMocks;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

public class NaverCustomAuthenticatorTest {

    private NaverCustomAuthenticator naverCustomAuthenticator;

    private static final String DUMMY_CLIENT_ID = "dummyClientId";
    private static final String DUMMY_CALLBACK_URL = "https://dummy-callback.com";
    private static final String DUMMY_AUTHORIZATION_EP = "https://dummy-auth-endpoint.com";
    private static final String DUMMY_IDP_NAME = "dummyIdP";
    private static final String DUMMY_STATE = "dummyState";

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private AuthenticationContext mockContext;

    @Mock
    private ExternalIdPConfig mockExternalIdPConfig;

    @BeforeTest
    public void init() {

        initMocks(this);
        naverCustomAuthenticator = spy(new NaverCustomAuthenticator());
    }

    @Test
    public void testCanHandle() {
        when(mockRequest.getParameter(NaverCustomAuthenticatorConstants.ACCESS_TOKEN_PARAM))
                .thenReturn("dummyAccessToken");
        assertTrue(naverCustomAuthenticator.canHandle(mockRequest));

        when(mockRequest.getParameter(NaverCustomAuthenticatorConstants.ACCESS_TOKEN_PARAM))
                .thenReturn(null);
        assertFalse(naverCustomAuthenticator.canHandle(mockRequest));
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {
        assertTrue(naverCustomAuthenticator.isAPIBasedAuthenticationSupported());
    }

    @Test
    public void testGetI18nKey() {
        NaverCustomAuthenticator authenticator = new NaverCustomAuthenticator();
        assertEquals(authenticator.getI18nKey(), NaverCustomAuthenticatorConstants.AUTHENTICATOR_I18N_KEY);
    }

    @Test
    public void testInitiateAuthenticationRequestSuccess() throws Exception {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(NaverCustomAuthenticatorConstants.CLIENT_ID, DUMMY_CLIENT_ID);
        authenticatorProperties.put(NaverCustomAuthenticatorConstants.CALLBACK_URL, DUMMY_CALLBACK_URL);

        when(mockContext.getAuthenticatorProperties()).thenReturn(authenticatorProperties);
        when(mockContext.getContextIdentifier()).thenReturn(DUMMY_STATE);
        doReturn(DUMMY_AUTHORIZATION_EP).when(naverCustomAuthenticator)
                .getAuthorizationServerEndpoint(authenticatorProperties);

        naverCustomAuthenticator.initiateAuthenticationRequest(mockRequest, mockResponse, mockContext);
        verify(mockResponse).sendRedirect(startsWith(DUMMY_AUTHORIZATION_EP));
    }

    @Test
    public void testGetAuthInitiationDataNotTrustedTokenIssuer() throws Exception {

        when(mockExternalIdPConfig.getIdPName()).thenReturn(DUMMY_IDP_NAME);
        when(mockContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);

        boolean isTrusted = invokeIsTrustedTokenIssuer(mockContext);
        assertFalse(isTrusted);

        Optional<AuthenticatorData> result = naverCustomAuthenticator.getAuthInitiationData(mockContext);

        assertTrue(result.isPresent());
        AuthenticatorData data = result.get();
        assertEquals(data.getIdp(), DUMMY_IDP_NAME);
        assertEquals(data.getPromptType(), FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
        assertNotNull(data.getAdditionalData());

        List<String> requiredParams = data.getRequiredParams();
        assertTrue(requiredParams.contains(NaverCustomAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE));
        assertTrue(requiredParams.contains(NaverCustomAuthenticatorConstants.OAUTH2_PARAM_STATE));
    }

    /**
     * mock the private method isTrustedTokenIssuer.
     */
    private boolean invokeIsTrustedTokenIssuer(AuthenticationContext context) throws Exception {
        Method method = NaverCustomAuthenticator.class.getDeclaredMethod("isTrustedTokenIssuer", AuthenticationContext.class);
        method.setAccessible(true);
        return (boolean) method.invoke(naverCustomAuthenticator, context);
    }
}
