/*
 * Copyright (c) 2023-2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.emailotp;

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.captcha.internal.CaptchaDataHolder;
import org.wso2.carbon.identity.captcha.util.CaptchaUtil;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.emailotp.util.AuthenticatorUtils;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.Claims.LOCALE_CLAIM;

/**
 * Class containing the test cases for EmailOTPAuthenticatorTest class.
 */
public class EmailOTPAuthenticatorTest {

    private EmailOTPAuthenticator emailOTPAuthenticator;
    private HttpServletRequest httpServletRequest;
    private HttpServletResponse httpServletResponse;
    private AuthenticationContext context;
    private ConfigurationFacade configurationFacade;
    private MultiAttributeLoginService multiAttributeLoginService;
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;
    private FrameworkServiceDataHolder frameworkServiceDataHolder;
    private RealmService realmService;
    private UserRealm userRealm;
    private AbstractUserStoreManager userStoreManager;
    private IdentityEventService identityEventService;
    private ClaimMetadataManagementService claimMetadataManagementService;
    private IdentityGovernanceService identityGovernanceService;
    private CaptchaDataHolder captchaDataHolder;
    private AuthenticatedUser authenticatedUserFromContext;
    private IdpManager idpManager;

    private MockedStatic<ConfigurationFacade> staticConfigurationFacade;
    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<FederatedAuthenticatorUtil> federatedAuthenticatorUtil;
    private MockedStatic<FileBasedConfigurationBuilder> staticFileBasedConfigurationBuilder;
    private MockedStatic<FrameworkServiceDataHolder> staticFrameworkServiceDataHolder;
    private MockedStatic<AuthenticatorUtils> authenticatorUtils;
    private MockedStatic<CaptchaDataHolder> staticCaptchaDataHolder;
    private MockedStatic<CaptchaUtil> captchaUtil;
    private MockedStatic<UserCoreUtil> userCoreUtil;
    private MockedStatic<LoggerUtils> mockLoggerUtils;

    private static final String USERNAME = "abc@gmail.com";
    private static final String EMAIL_ADDRESS = "abc@gmail.com";
    private static final String TENANT_DOMAIN = "wso2.org";
    private static final int TENANT_ID = -1234;
    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String DEFAULT_USER_STORE = "DEFAULT";
    private static final String DUMMY_LOGIN_PAGE_URL = "dummyLoginPageURL";
    private static final String SAMPLE_LOCALE = "fr-FR";

    @BeforeMethod
    public void setUp() {
        authenticatedUserFromContext = mock(AuthenticatedUser.class);
        emailOTPAuthenticator = new EmailOTPAuthenticator();
        httpServletRequest = mock(HttpServletRequest.class);
        httpServletResponse = mock(HttpServletResponse.class);
        context = new AuthenticationContext();
        configurationFacade = mock(ConfigurationFacade.class);
        realmService = mock(RealmService.class);
        userRealm = mock(UserRealm.class);
        userStoreManager = mock(AbstractUserStoreManager.class);
        fileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        frameworkServiceDataHolder = mock(FrameworkServiceDataHolder.class);
        identityEventService = mock(IdentityEventService.class);
        claimMetadataManagementService = mock(ClaimMetadataManagementService.class);
        identityGovernanceService = mock(IdentityGovernanceService.class);
        captchaDataHolder = mock(CaptchaDataHolder.class);
        multiAttributeLoginService = mock(MultiAttributeLoginService.class);
        idpManager = mock(IdpManager.class);

        staticConfigurationFacade = mockStatic(ConfigurationFacade.class);
        frameworkUtils = mockStatic(FrameworkUtils.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        federatedAuthenticatorUtil = mockStatic(FederatedAuthenticatorUtil.class);
        mockLoggerUtils = mockStatic(LoggerUtils.class);
        staticFileBasedConfigurationBuilder = mockStatic(FileBasedConfigurationBuilder.class);
        staticFrameworkServiceDataHolder = mockStatic(FrameworkServiceDataHolder.class);
        authenticatorUtils = mockStatic(AuthenticatorUtils.class);
        staticCaptchaDataHolder = mockStatic(CaptchaDataHolder.class);
        captchaUtil = mockStatic(CaptchaUtil.class);
        userCoreUtil = mockStatic(UserCoreUtil.class, Mockito.CALLS_REAL_METHODS);

        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        when(frameworkServiceDataHolder.getMultiAttributeLoginService()).thenReturn(multiAttributeLoginService);
        when(multiAttributeLoginService.isEnabled(TENANT_DOMAIN)).thenReturn(false);
    }

    @DataProvider(name = "authenticatorProvider")
    public Object[][] provideAuthenticators() {
        return new Object[][]{
                {"sms-otp-authenticator"},
                {"email-otp-authenticator"}
        };
    }

    @Test(description = "Test isRetrying in OTP Authenticators",
            dataProvider = "authenticatorProvider",
            expectedExceptions = NullPointerException.class)
    public void testIsRetryingInOTPAuthenticators(String currentAuthenticator)
            throws AuthenticationFailedException, LogoutFailedException {

        setAuthenticatorConfig();
        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn(String.valueOf(true));
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);

        context.setCurrentAuthenticator(currentAuthenticator);

        emailOTPAuthenticator.process(httpServletRequest, httpServletResponse, context);
        Assert.assertFalse(context.isRetrying());
    }

    @Test(description = "Test case for canHandle() method false case.")
    public void testCanHandleFalse() {
        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn(null);
        when(httpServletRequest.getParameter(AuthenticatorConstants.CODE)).thenReturn(null);
        when(httpServletRequest.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(null);
        Assert.assertFalse(emailOTPAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test case for process() method when authenticated user is null " +
            "and the username of an existing user is entered into the IdF page.")
    public void testProcessWithoutAuthenticatedUserAndValidUsernameEntered()
            throws Exception {

        AuthenticatorConfig authenticatorConfig = setAuthenticatorConfig();
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);

        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertTrue(((boolean) context.getProperty(
                AuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR)));

        User user = new User(UUID.randomUUID().toString(), USERNAME, null);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(TENANT_DOMAIN);

        List<User> userList = new ArrayList<>();
        userList.add(user);

        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EMAIL_ADDRESS_CLAIM, EMAIL_ADDRESS);

        context.setTenantDomain(TENANT_DOMAIN);
        configureAuthenticatorDataHolder();

        when(FrameworkUtils.preprocessUsername(USERNAME, context)).thenReturn(USERNAME + "@" + TENANT_DOMAIN);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(AuthenticatorUtils.isAccountLocked(any())).thenReturn(false);
        when(CaptchaDataHolder.getInstance()).thenReturn(captchaDataHolder);
        when(FrameworkServiceDataHolder.getInstance()).thenReturn(frameworkServiceDataHolder);
        when(httpServletRequest.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(USERNAME);
        when(frameworkServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserListWithID(USERNAME_CLAIM, USERNAME, null)).thenReturn(userList);
        when(userStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(claimMap);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        userCoreUtil.when(UserCoreUtil::getDomainFromThreadLocal).thenReturn(DEFAULT_USER_STORE);
        mockMultiAttributeLoginService();
        status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse, context);
        assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertTrue((Boolean.parseBoolean(String.valueOf(context.getProperty(
                AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP)))));
    }

    @Test(description = "Test case for process() method when authenticated user is null " +
            "and the username of an invalid user is entered into the IdF page.")
    public void testProcessWithoutAuthenticatedUserAndInvalidUsernameEntered()
            throws Exception {

        AuthenticatorConfig authenticatorConfig = setAuthenticatorConfig();

        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EMAIL_ADDRESS_CLAIM, EMAIL_ADDRESS);

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);

        emailOTPAuthenticator.process(httpServletRequest, httpServletResponse, context);

        when(FrameworkServiceDataHolder.getInstance()).thenReturn(frameworkServiceDataHolder);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(frameworkServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(httpServletRequest.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(USERNAME);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserListWithID(USERNAME_CLAIM, USERNAME, null)).thenReturn(new ArrayList<>());
        when(userStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(claimMap);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        when(FrameworkUtils.preprocessUsername(USERNAME, context)).thenReturn(USERNAME + "@" + TENANT_DOMAIN);
        when(CaptchaDataHolder.getInstance()).thenReturn(captchaDataHolder);
        AuthenticatorDataHolder.setIdentityGovernanceService(identityGovernanceService);
        mockMultiAttributeLoginService();

        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertTrue((Boolean.parseBoolean(String.valueOf(context.getProperty(
                AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP)))));
    }

    /**
     * Set email OTP authenticator as first factor in step config map
     *
     * @param authenticatorConfig Authenticator Config containing email OTP authenticator
     * @param context             Authentication Context
     */
    private void setStepConfigWithEmailOTPAuthenticator(AuthenticatorConfig authenticatorConfig,
                                                        AuthenticationContext context) {

        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();

        StepConfig emailOTPStep = new StepConfig();
        authenticatorConfig.setName(AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_NAME);
        List<AuthenticatorConfig> authenticatorList = new ArrayList<>();
        authenticatorList.add(authenticatorConfig);
        emailOTPStep.setAuthenticatorList(authenticatorList);
        emailOTPStep.setSubjectAttributeStep(true);
        stepConfigMap.put(1, emailOTPStep);

        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(1);

        ApplicationConfig applicationConfig = mock(ApplicationConfig.class);
        when(applicationConfig.isSaaSApp()).thenReturn(false);
        context.getSequenceConfig().setApplicationConfig(applicationConfig);
    }

    private void mockMultiAttributeLoginService() {

        when(FrameworkServiceDataHolder.getInstance()).thenReturn(frameworkServiceDataHolder);
        when(frameworkServiceDataHolder.getMultiAttributeLoginService()).thenReturn(multiAttributeLoginService);
        when(multiAttributeLoginService.isEnabled(anyString())).thenReturn(false);
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        boolean isAPIBasedAuthenticationSupported = emailOTPAuthenticator.isAPIBasedAuthenticationSupported();
        Assert.assertTrue(isAPIBasedAuthenticationSupported);
    }

    @Test
    public void testGetAuthInitiationData() throws AuthenticationFailedException {

        Optional<AuthenticatorData> authenticatorData = emailOTPAuthenticator.getAuthInitiationData(context);
        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                AuthenticatorConstants.USER_NAME, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, AuthenticatorConstants.USERNAME_PARAM);
        authenticatorParamMetadataList.add(usernameMetadata);

        assertEquals(authenticatorDataObj.getName(), AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_NAME);
        assertEquals(authenticatorDataObj.getDisplayName(),
                AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_FRIENDLY_NAME,
                "Authenticator display name should match.");
        assertEquals(authenticatorDataObj.getAuthParams().size(), authenticatorParamMetadataList.size(),
                "Size of lists should be equal.");
        assertEquals(authenticatorDataObj.getPromptType(),
                FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        assertEquals(authenticatorDataObj.getRequiredParams().size(),
                1);
        for (int i = 0; i < authenticatorParamMetadataList.size(); i++) {
            AuthenticatorParamMetadata expectedParam = authenticatorParamMetadataList.get(i);
            AuthenticatorParamMetadata actualParam = authenticatorDataObj.getAuthParams().get(i);

            assertEquals(actualParam.getName(), expectedParam.getName(), "Parameter name should match.");
            assertEquals(actualParam.getType(), expectedParam.getType(), "Parameter type should match.");
            assertEquals(actualParam.getParamOrder(), expectedParam.getParamOrder(),
                    "Parameter order should match.");
            assertEquals(actualParam.isConfidential(), expectedParam.isConfidential(),
                    "Parameter mandatory status should match.");
        }
    }

    @DataProvider(name = "testSetAssociatedLocaleDataProvider")
    public Object[][] testSetAssociatedLocaleDataProvider() {

        return new Object[][] {
                { true },   // For provisioned users with Locale changed in myaccount.
                { false }   // For provisioned users without associated locale.
        };
    }

    @Test(dataProvider = "testSetAssociatedLocaleDataProvider")
    public void testSetAssociatedLocaleForProvisionedUsers(boolean hasAssociatedLocale) throws Exception {

        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EMAIL_ADDRESS_CLAIM, EMAIL_ADDRESS);
        if (hasAssociatedLocale) {
            claimMap.put(LOCALE_CLAIM, SAMPLE_LOCALE);
        }
        setAuthenticatorConfig();
        configureAuthenticatedUser();
        configureAuthenticatorDataHolder();
        configureIdentityProvider();

        IdentityProvider identityProvider = new IdentityProvider();
        JustInTimeProvisioningConfig justInTimeProvisioningConfig = new JustInTimeProvisioningConfig();
        justInTimeProvisioningConfig.setProvisioningUserStore(USER_STORE_DOMAIN);
        identityProvider.setJustInTimeProvisioningConfig(justInTimeProvisioningConfig);
        when(idpManager.getIdPByName(any(), any())).thenReturn(identityProvider);

        when(FederatedAuthenticatorUtil.getLoggedInFederatedUser(any())).thenReturn(USERNAME);
        when(FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(any(), any())).thenReturn(USERNAME);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(claimMap);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(CaptchaDataHolder.getInstance()).thenReturn(captchaDataHolder);

        emailOTPAuthenticator.process(httpServletRequest, httpServletResponse, context);

        ArgumentCaptor<Event> eventCaptor = ArgumentCaptor.forClass(Event.class);
        verify(identityEventService, times(2)).handleEvent(eventCaptor.capture());
        Event capturedEvent = eventCaptor.getValue();

        Map<String, Object> properties = capturedEvent.getEventProperties();
        if (hasAssociatedLocale) {
            assertNotNull(properties.get(AuthenticatorConstants.LOCAL_CLAIM_VALUE));
        } else {
            assertNull(properties.get(AuthenticatorConstants.LOCAL_CLAIM_VALUE));
        }
    }

    private AuthenticatorConfig setAuthenticatorConfig() {

        Map<String, String> parameters = new HashMap<>();
        parameters.put("BlockedUserStoreDomains", "");

        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        authenticatorConfig.setParameterMap(parameters);
        setStepConfigWithEmailOTPAuthenticator(authenticatorConfig, context);

        return  authenticatorConfig;
    }

    private void configureAuthenticatorDataHolder() {

        AuthenticatorDataHolder.setRealmService(realmService);
        AuthenticatorDataHolder.setIdentityEventService(identityEventService);
        AuthenticatorDataHolder.setClaimMetadataManagementService(claimMetadataManagementService);
        AuthenticatorDataHolder.setIdentityGovernanceService(identityGovernanceService);
        AuthenticatorDataHolder.setIdpManager(idpManager);
    }

    private void configureAuthenticatedUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
        authenticatedUser.setUserName(USERNAME);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN);
        authenticatedUser.setFederatedUser(true);
        context.setSubject(authenticatedUser);
    }

    private void configureIdentityProvider() throws IdentityProviderManagementException {

        IdentityProvider identityProvider = new IdentityProvider();
        JustInTimeProvisioningConfig justInTimeProvisioningConfig = new JustInTimeProvisioningConfig();
        justInTimeProvisioningConfig.setProvisioningUserStore(USER_STORE_DOMAIN);
        identityProvider.setJustInTimeProvisioningConfig(justInTimeProvisioningConfig);
        when(idpManager.getIdPByName(any(), any())).thenReturn(identityProvider);
    }

    @AfterMethod
    public void cleanUp() {

        staticConfigurationFacade.close();
        frameworkUtils.close();
        identityTenantUtil.close();
        federatedAuthenticatorUtil.close();
        staticFileBasedConfigurationBuilder.close();
        staticFrameworkServiceDataHolder.close();
        authenticatorUtils.close();
        staticCaptchaDataHolder.close();
        captchaUtil.close();
        userCoreUtil.close();
        mockLoggerUtils.close();
    }
}
