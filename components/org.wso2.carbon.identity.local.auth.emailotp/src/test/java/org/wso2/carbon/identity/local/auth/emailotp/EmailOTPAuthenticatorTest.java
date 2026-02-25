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
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.captcha.internal.CaptchaDataHolder;
import org.wso2.carbon.identity.captcha.util.CaptchaUtil;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.emailotp.util.AuthenticatorUtils;
import org.wso2.carbon.identity.local.auth.emailotp.util.CommonUtils;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
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
import static org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator.SKIP_RETRY_FROM_AUTHENTICATOR;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.CODE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.Claims.EMAIL_OTP_LAST_SENT_TIME_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.Claims.EMAIL_OTP_RESEND_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.Claims.LOCALE_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.HIDE_USER_EXISTENCE_CONFIG;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.OTP_RESEND_ATTEMPTS;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.OTP_RETRY_ATTEMPTS;

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
    private IdentityConfigParser identityConfigParser;
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
    private AuthenticatedUser authenticatedUser;

    private MockedStatic<ConfigurationFacade> staticConfigurationFacade;
    private MockedStatic<IdentityConfigParser> staticIdentityConfigParser;
    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;
    private MockedStatic<FederatedAuthenticatorUtil> federatedAuthenticatorUtil;
    private MockedStatic<FileBasedConfigurationBuilder> staticFileBasedConfigurationBuilder;
    private MockedStatic<FrameworkServiceDataHolder> staticFrameworkServiceDataHolder;
    private MockedStatic<AuthenticatorUtils> authenticatorUtils;
    private MockedStatic<CommonUtils> commonUtils;
    private MockedStatic<CaptchaDataHolder> staticCaptchaDataHolder;
    private MockedStatic<CaptchaUtil> captchaUtil;
    private MockedStatic<UserCoreUtil> userCoreUtil;
    private MockedStatic<LoggerUtils> mockLoggerUtils;

    private static final String USERNAME = "abc@gmail.com";
    private static final String USER_ID = "47f02f57-a6a1-4677-8de1-8cfe31b42456";
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
        identityConfigParser = mock(IdentityConfigParser.class);
        frameworkServiceDataHolder = mock(FrameworkServiceDataHolder.class);
        identityEventService = mock(IdentityEventService.class);
        claimMetadataManagementService = mock(ClaimMetadataManagementService.class);
        identityGovernanceService = mock(IdentityGovernanceService.class);
        captchaDataHolder = mock(CaptchaDataHolder.class);
        multiAttributeLoginService = mock(MultiAttributeLoginService.class);
        idpManager = mock(IdpManager.class);
        authenticatedUser = mock(AuthenticatedUser.class);

        staticConfigurationFacade = mockStatic(ConfigurationFacade.class);
        staticIdentityConfigParser = mockStatic(IdentityConfigParser.class);
        frameworkUtils = mockStatic(FrameworkUtils.class);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);
        federatedAuthenticatorUtil = mockStatic(FederatedAuthenticatorUtil.class);
        mockLoggerUtils = mockStatic(LoggerUtils.class);
        staticFileBasedConfigurationBuilder = mockStatic(FileBasedConfigurationBuilder.class);
        staticFrameworkServiceDataHolder = mockStatic(FrameworkServiceDataHolder.class);
        authenticatorUtils = mockStatic(AuthenticatorUtils.class);
        commonUtils = mockStatic(CommonUtils.class);
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
            dataProvider = "authenticatorProvider")
    public void testIsRetryingInOTPAuthenticators(String currentAuthenticator)
            throws AuthenticationFailedException, LogoutFailedException {

        setAuthenticatorConfig();
        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn(String.valueOf(true));
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);

        context.setCurrentAuthenticator(currentAuthenticator);

        try {
            emailOTPAuthenticator.process(httpServletRequest, httpServletResponse, context);
        } catch (NullPointerException ignored) {
        }
        Assert.assertFalse(context.isRetrying());
    }

    @Test(description = "Test case for canHandle() method false case.")
    public void testCanHandleFalse() {
        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn(null);
        when(httpServletRequest.getParameter(AuthenticatorConstants.CODE)).thenReturn(null);
        when(httpServletRequest.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(null);
        Assert.assertFalse(emailOTPAuthenticator.canHandle(httpServletRequest));
    }

    @DataProvider(name = "OTPParams")
    public Object[][] provideOTPParams() {

        return new Object[][]{
                {AuthenticatorConstants.CODE},
                {AuthenticatorConstants.CODE_LOWERCASE}
        };
    }

    @Test(description = "Test case for getParameterNames() method.", dataProvider = "OTPParams")
    public void testGetParameterNames(String otpParam) {

        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn(AuthenticatorConstants.RESEND);
        when(httpServletRequest.getParameterNames()).thenReturn(Collections.enumeration(
                Collections.singletonList(otpParam)));
        Assert.assertTrue(emailOTPAuthenticator.canHandle(httpServletRequest));
    }

    @Test(
            description = "Test case for processAuthenticationResponse() method when the OTP token is empty " +
                    "for the authenticated user, expecting an InvalidCredentialsException.",
            expectedExceptions = InvalidCredentialsException.class,
            expectedExceptionsMessageRegExp = "OTP token is empty for user: .*"
    )
    public void testProcessAuthenticationResponseWithEmptyOtpToken() throws AuthenticationFailedException {

        setAuthenticatorConfig();
        configureAuthenticatedUser(false);
        emailOTPAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @Test(dataProvider = "ScenarioDataProvider", description = "Test case for resolveScenario() method.")
    public void testResolveScenario(String authenticator, boolean isLogoutRequest, boolean isRetrying,
                                    String resendCode, String codeParam, String code,
                                    AuthenticatorConstants.AuthenticationScenarios expectedScenario) throws Exception {

        context.setCurrentAuthenticator(authenticator);
        context.setRetrying(isRetrying);
        context.setLogoutRequest(isLogoutRequest);

        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn(resendCode);
        when(httpServletRequest.getParameter(codeParam)).thenReturn(code);
        when(httpServletRequest.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(USERNAME);

        Method method = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("resolveScenario", HttpServletRequest.class, AuthenticationContext.class);
        method.setAccessible(true);
        Object result = method.invoke(emailOTPAuthenticator, httpServletRequest, context);
        Assert.assertEquals(result, expectedScenario);
    }

    @DataProvider(name = "ScenarioDataProvider")
    public Object[][] scenarioDataProvider() {

        //AuthenticatorName, isLogoutRequest, isRetrying, resendCode, codeParam, code, expectedScenario
        return new Object[][]{
                // Initial OTP scenario where no code is available
                {"previousAuthenticator", false, false, null, "OTPCode", null,
                        AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP},
                // Initial OTP scenario where code from previous authenticator is available as OTPCode
                {"previousOTPAuthenticator", false, false, null, "OTPCode", "1234",
                        AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP},
                // Logout scenario
                {"randomAuthenticator", true, true, "true", "OTPCode", "1234",
                        AuthenticatorConstants.AuthenticationScenarios.LOGOUT},
                // Retry scenario
                {EMAIL_OTP_AUTHENTICATOR_NAME, false, true, null, "OTPCode", "1234",
                        AuthenticatorConstants.AuthenticationScenarios.SUBMIT_OTP},
                // Retry is incorrectly set due to previous authenticator
                {"previousAuthenticator", false, true, null, "OTPCode", null,
                        AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP},
                // Resend scenario
                {EMAIL_OTP_AUTHENTICATOR_NAME, false, true, "true", "OTPCode", "1234",
                        AuthenticatorConstants.AuthenticationScenarios.RESEND_OTP},
        };
    }

    @Test(dataProvider = "IDFInitiationDataProvider")
    public void testInitiateAuthenticationRequestForIDFInitiation(boolean isUsernameAvailable, boolean isUserAvailable,
                                                                  Boolean initialIsIDFInitiatedFromAuthenticator,
                                                                  Boolean expectedIsIDFInitiatedFromAuthenticator)
            throws Exception {

        context.setProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR, initialIsIDFInitiatedFromAuthenticator);
        if (isUsernameAvailable) {
            when(httpServletRequest.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(USERNAME);
        } else {
            when(httpServletRequest.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(null);
        }
        context.setCurrentStep(2);
        SequenceConfig sequenceConfig = new SequenceConfig();
        StepConfig stepConfig = new StepConfig();
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        stepConfigMap.put(2, stepConfig);
        sequenceConfig.setStepMap(stepConfigMap);
        context.setSequenceConfig(sequenceConfig);

        if (isUserAvailable) {
            AuthenticatedUser user = new AuthenticatedUser();
            user.setFederatedUser(true);
            user.setAuthenticatedSubjectIdentifier(USERNAME);
            stepConfig.setAuthenticatedUser(user);
        }

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);

        try {
            Method method = emailOTPAuthenticator.getClass()
                    .getDeclaredMethod("initiateAuthenticationRequest",
                            HttpServletRequest.class,
                            HttpServletResponse.class,
                            AuthenticationContext.class);
            method.setAccessible(true);
            method.invoke(emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
        } catch (InvocationTargetException e) {
            // Ignore the exception
        }

        Assert.assertEquals(context.getProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR),
                expectedIsIDFInitiatedFromAuthenticator);

    }

    @DataProvider(name = "IDFInitiationDataProvider")
    public Object[][] iDFInitiationDataProvider() {

        return new Object[][]{
                {true, false, true, null},
                {false, false, null, true},
                {false, true, null, null},
        };
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
        Assert.assertTrue(((boolean) context.getProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR)));

        User user = new User(UUID.randomUUID().toString(), USERNAME, null);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(TENANT_DOMAIN);

        List<User> userList = new ArrayList<>();
        userList.add(user);

        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EMAIL_ADDRESS_CLAIM, EMAIL_ADDRESS);

        context.setTenantDomain(TENANT_DOMAIN);
        configureAuthenticatorDataHolder();

        when(FrameworkUtils.preprocessUsernameWithContextTenantDomain(USERNAME, context)).thenReturn(
                USERNAME + "@" + TENANT_DOMAIN);
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
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        Map<String, Object> configs = new HashMap<>();
        configs.put(HIDE_USER_EXISTENCE_CONFIG, "true");
        when(identityConfigParser.getConfiguration()).thenReturn(configs);
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
        when(FrameworkUtils.preprocessUsernameWithContextTenantDomain(USERNAME, context)).thenReturn(
                USERNAME + "@" + TENANT_DOMAIN);
        when(CaptchaDataHolder.getInstance()).thenReturn(captchaDataHolder);
        AuthenticatorDataHolder.setIdentityGovernanceService(identityGovernanceService);
        mockMultiAttributeLoginService();

        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);
        assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertTrue((Boolean.parseBoolean(String.valueOf(context.getProperty(
                AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP)))));
    }

    @Test(description = "Test case for process() method when Email OTP is the first step " +
            "but not the subject identifier step. This should prompt the identifier (IDF) page.")
    public void testProcessWithEmailOTPAsFirstStepAndSecondStepAsSubjectIdentifier()
            throws Exception {

        setStepConfigWithEmailOTPAsFirstStepAndSubjectIdentifierAsSecondStep();

        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);

        // No username is provided in the request (initial request).
        when(httpServletRequest.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(null);

        AuthenticatorFlowStatus status = emailOTPAuthenticator.process(httpServletRequest, httpServletResponse,
                context);

        // Verify that the flow is incomplete and the user is being prompted for identifier.
        assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
        Assert.assertTrue((Boolean) context.getProperty(IS_IDF_INITIATED_FROM_AUTHENTICATOR),
                "Expected the authenticator to initiate IDF (Identifier First) flow.");
    }

    private void setStepConfigWithEmailOTPAsFirstStepAndSubjectIdentifierAsSecondStep() {

        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();

        // Step 1: Email OTP authenticator (NOT subject identifier step).
        StepConfig emailOTPStep = new StepConfig();
        AuthenticatorConfig emailOTPAuthConfig = new AuthenticatorConfig();
        emailOTPAuthConfig.setName(EMAIL_OTP_AUTHENTICATOR_NAME);
        List<AuthenticatorConfig> emailOTPAuthenticatorList = new ArrayList<>();
        emailOTPAuthenticatorList.add(emailOTPAuthConfig);
        emailOTPStep.setAuthenticatorList(emailOTPAuthenticatorList);
        emailOTPStep.setSubjectAttributeStep(false);
        stepConfigMap.put(1, emailOTPStep);

        // Step 2: Another authenticator (subject identifier step)
        StepConfig secondStep = new StepConfig();
        AuthenticatorConfig basicAuthConfig = new AuthenticatorConfig();
        basicAuthConfig.setName("BasicAuthenticator");
        List<AuthenticatorConfig> basicAuthenticatorList = new ArrayList<>();
        basicAuthenticatorList.add(basicAuthConfig);
        secondStep.setAuthenticatorList(basicAuthenticatorList);
        secondStep.setSubjectAttributeStep(true); // This is the subject identifier step
        stepConfigMap.put(2, secondStep);

        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        context.setSequenceConfig(sequenceConfig);
        context.setCurrentStep(1); // Currently executing step 1 (Email OTP)

        ApplicationConfig applicationConfig = mock(ApplicationConfig.class);
        when(applicationConfig.isSaaSApp()).thenReturn(false);
        context.getSequenceConfig().setApplicationConfig(applicationConfig);
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
        authenticatorConfig.setName(EMAIL_OTP_AUTHENTICATOR_NAME);
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


    @DataProvider(name = "resendLimitDataProvider")
    public Object[][] resendLimitDataProvider() {

        return new Object[][]{

                {5, 0, false},
                {3, 3, true}, //This is due to adding one more retry attempt before the check happens
                {8, 3, true},
                {4, 3, true},
                {2, 5, false}
        };
    }
    @Test(dataProvider = "resendLimitDataProvider",
            description = "Test resend OTP resend limit logic in EmailOTPAuthenticator with full context and mocks")
    public void testResendAttemptsValidation(int currentAttempts, int maxAllowed,
                                             boolean shouldExceedLimit) throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);
        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EMAIL_ADDRESS_CLAIM, EMAIL_ADDRESS);
        claimMap.put(EMAIL_OTP_RESEND_ATTEMPTS_CLAIM, String.valueOf(currentAttempts));
        claimMap.put(EMAIL_OTP_LAST_SENT_TIME_CLAIM, String.valueOf(System.currentTimeMillis()));
        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");

        // Set a prior message
        AuthenticatorMessage priorMessage = new AuthenticatorMessage(
                FrameworkConstants.AuthenticatorMessageType.INFO, "EmailOTPSent", "Email sent", null);
        context.setProperty("authenticatorMessage", priorMessage);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);

        // Set current attempts to max allowed
        context.setProperty(AuthenticatorConstants.OTP_RESEND_ATTEMPTS, currentAttempts);

        // Mock config to return maxAllowed for resend attempts
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_RESEND_ATTEMPTS_COUNT,
                        TENANT_DOMAIN
                )
        ).thenReturn(String.valueOf(maxAllowed));

        // Required by isUserBasedOTPResendBlockingEnabled
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getSkipResendBlockTimeParam(any()))
                .thenReturn("false");
        // Disable context-based resend/retry blocking
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedResendAttemptsLimit(any()))
                .thenReturn(-1);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(-1);

        authenticatorUtils.when(() ->
                        AuthenticatorUtils.getEmailOTPLoginPageUrl(any(), anyString()))
                .thenReturn("https://localhost:9443/authenticationendpoint/email-otp.jsp");

        // Simulate resend scenario
        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");

        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(claimMap);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        AuthenticatorConfig authenticatorConfig = setAuthenticatorConfig();
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

        when(CaptchaDataHolder.getInstance()).thenReturn(captchaDataHolder);
        when(captchaDataHolder.isForcefullyEnabledRecaptchaForAllTenants()).thenReturn(true);

        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(identityConfigParser.getConfiguration()).thenReturn(new HashMap<>());
        Method method = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("initiateAuthenticationRequest",
                        HttpServletRequest.class,
                        HttpServletResponse.class,
                        AuthenticationContext.class);
        method.setAccessible(true);

        try {
            method.invoke(emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
        } catch (InvocationTargetException ignored) { }

        if (shouldExceedLimit) {
            Assert.assertNull(context.getProperty(AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP),
                    "AuthenticatorMessage should be null when resend attempts exceed maximum.");
        } else {
            Assert.assertTrue(
                    Boolean.parseBoolean((String) context.getProperty(AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP)),
                    "AuthenticatorMessage should not be null when resend attempts have NOT exceeded maximum.");
        }
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

        assertEquals(authenticatorDataObj.getName(), EMAIL_OTP_AUTHENTICATOR_NAME);
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
        configureAuthenticatedUser(true);
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
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        Map<String, Object> configs = new HashMap<>();
        configs.put(HIDE_USER_EXISTENCE_CONFIG, "false");
        when(identityConfigParser.getConfiguration()).thenReturn(configs);

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

    private void configureAuthenticatedUser(boolean isFederated) {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(USER_STORE_DOMAIN);
        authenticatedUser.setUserName(USERNAME);
        authenticatedUser.setUserId(USER_ID);
        authenticatedUser.setTenantDomain(TENANT_DOMAIN);
        authenticatedUser.setFederatedUser(isFederated);
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
        staticIdentityConfigParser.close();
        frameworkUtils.close();
        identityTenantUtil.close();
        federatedAuthenticatorUtil.close();
        staticFileBasedConfigurationBuilder.close();
        staticFrameworkServiceDataHolder.close();
        authenticatorUtils.close();
        commonUtils.close();
        staticCaptchaDataHolder.close();
        captchaUtil.close();
        userCoreUtil.close();
        mockLoggerUtils.close();
    }

    // -------------------------------------------------------------------------
    // Context-based resend limit control tests
    // -------------------------------------------------------------------------

    @DataProvider(name = "contextResendLimitDataProvider")
    public Object[][] contextResendLimitDataProvider() {

        // currentContextAttempts, maxAllowedByRuntime, shouldBlock
        return new Object[][]{
                // Not yet at limit → OTP sent, redirected to login page
                {0, 3, false},
                {2, 3, false},
                // At limit → blocked, no redirect to OTP page
                {3, 3, true},
                {5, 3, true},
        };
    }

    @Test(dataProvider = "contextResendLimitDataProvider",
            description = "Test context-based OTP resend limit: when OTP_RESEND_ATTEMPTS in context reaches "
                    + "the runtime-param limit the authenticator must NOT redirect to the OTP page.")
    public void testContextBasedResendLimitBlocking(int currentContextAttempts, int maxAllowed,
                                                    boolean shouldBlock) throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);

        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);

        // Pre-set context resend counter
        context.setProperty(OTP_RESEND_ATTEMPTS, currentContextAttempts);

        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");

        // Disable user-based resend blocking by returning 0 for the resend attempts config
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_RESEND_ATTEMPTS_COUNT, TENANT_DOMAIN))
                .thenReturn("0");

        // Return maxAllowed via runtime param (context-based)
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedResendAttemptsLimit(any()))
                .thenReturn(maxAllowed);
        // Retry limit disabled
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(-1);
        // skipResendBlockTime = false (user-based blocking is not skipped)
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getSkipResendBlockTimeParam(any()))
                .thenReturn("false");

        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailOTPLoginPageUrl(any(), anyString()))
                .thenReturn("https://localhost:9443/authenticationendpoint/email-otp.jsp");
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailOTPErrorPageUrl(any(), anyString()))
                .thenReturn("https://localhost:9443/authenticationendpoint/email_otp_error.do");

        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(new HashMap<>());

        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        AuthenticatorConfig authenticatorConfig = setAuthenticatorConfig();
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        when(CaptchaDataHolder.getInstance()).thenReturn(captchaDataHolder);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(identityConfigParser.getConfiguration()).thenReturn(new HashMap<>());

        Method method = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("initiateAuthenticationRequest",
                        HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class);
        method.setAccessible(true);
        try {
            method.invoke(emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
        } catch (InvocationTargetException ignored) {
        }

        if (shouldBlock) {
            Assert.assertFalse(
                    Boolean.parseBoolean(
                            String.valueOf(context.getProperty(AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP))),
                    "Should NOT redirect to OTP page when context-based resend limit is exceeded.");
        } else {
            Assert.assertTrue(
                    Boolean.parseBoolean(
                            String.valueOf(context.getProperty(AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP))),
                    "Should redirect to OTP page when context-based resend limit is NOT exceeded.");
        }
    }

    @Test(description = "Test that OTP_RESEND_ATTEMPTS in context is incremented on each successful resend "
            + "when user-based blocking is disabled and context-based limit is active.")
    public void testContextResendCounterIncrement() throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);

        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);
        context.setProperty(OTP_RESEND_ATTEMPTS, 1);

        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");

        // Disable user-based blocking
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_RESEND_ATTEMPTS_COUNT, TENANT_DOMAIN))
                .thenReturn("0");
        // Context limit = 5 (not yet reached)
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedResendAttemptsLimit(any()))
                .thenReturn(5);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(-1);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getSkipResendBlockTimeParam(any()))
                .thenReturn("false");
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailOTPLoginPageUrl(any(), anyString()))
                .thenReturn("https://localhost:9443/authenticationendpoint/email-otp.jsp");

        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(new HashMap<>());
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        AuthenticatorConfig resendCounterIncrementConfig = setAuthenticatorConfig();
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(resendCounterIncrementConfig);
        when(CaptchaDataHolder.getInstance()).thenReturn(captchaDataHolder);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(identityConfigParser.getConfiguration()).thenReturn(new HashMap<>());

        Method contextResendCounterIncrementMethod = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("initiateAuthenticationRequest",
                        HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class);
        contextResendCounterIncrementMethod.setAccessible(true);
        try {
            contextResendCounterIncrementMethod.invoke(
                    emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
        } catch (InvocationTargetException ignored) {
        }

        // Counter should have been incremented from 1 → 2
        Assert.assertEquals(context.getProperty(OTP_RESEND_ATTEMPTS), 2,
                "OTP_RESEND_ATTEMPTS context counter should be incremented after a successful resend.");
    }

    @Test(description = "Test that the terminateOnResendLimitExceeded runtime param causes an "
            + "AuthenticationFailedException (flow termination) instead of a redirect to error page.")
    public void testTerminateOnContextResendLimitExceeded() throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);

        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);
        // Already at limit
        context.setProperty(OTP_RESEND_ATTEMPTS, 3);

        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");

        // Disable user-based blocking
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_RESEND_ATTEMPTS_COUNT, TENANT_DOMAIN))
                .thenReturn("0");
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedResendAttemptsLimit(any()))
                .thenReturn(3);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(-1);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getSkipResendBlockTimeParam(any()))
                .thenReturn("false");
        // Enable terminate-on-resend-limit-exceeded
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getTerminateOnResendLimitExceededParam(any()))
                .thenReturn("true");

        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(new HashMap<>());
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        AuthenticatorConfig terminateResendConfig = setAuthenticatorConfig();
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(terminateResendConfig);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(identityConfigParser.getConfiguration()).thenReturn(new HashMap<>());

        Method terminateResendMethod = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("initiateAuthenticationRequest",
                        HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class);
        terminateResendMethod.setAccessible(true);

        try {
            terminateResendMethod.invoke(emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
            Assert.fail("Expected AuthenticationFailedException to be thrown when terminateOnResendLimitExceeded=true");
        } catch (InvocationTargetException e) {
            Assert.assertTrue(e.getCause() instanceof AuthenticationFailedException,
                    "Expected AuthenticationFailedException when terminateOnResendLimitExceeded is true.");
        }

        // isRetrying must be set to false (flow terminated)
        Assert.assertFalse(context.isRetrying(),
                "isRetrying should be false when resend limit exceeded with terminateFlow=true.");
    }

    @Test(description = "Test that skipResendBlockTime=true disables user-based OTP resend blocking "
            + "even when the resend count in user store is at or above the configured maximum.")
    public void testSkipResendBlockTimeDisablesUserBasedBlocking() throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);

        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);
        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");

        Map<String, String> claimMap = new HashMap<>();
        // Resend count in store exceeds configured max
        claimMap.put(EMAIL_OTP_RESEND_ATTEMPTS_CLAIM, "10");
        claimMap.put(EMAIL_OTP_LAST_SENT_TIME_CLAIM, String.valueOf(System.currentTimeMillis()));
        claimMap.put(FrameworkConstants.EMAIL_ADDRESS_CLAIM, EMAIL_ADDRESS);

        // User-based max is 3 — would normally block
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_RESEND_ATTEMPTS_COUNT, TENANT_DOMAIN))
                .thenReturn("3");
        // Skip the block window check
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getSkipResendBlockTimeParam(any()))
                .thenReturn("true");
        // No context-based limit
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedResendAttemptsLimit(any()))
                .thenReturn(-1);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(-1);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailOTPLoginPageUrl(any(), anyString()))
                .thenReturn("https://localhost:9443/authenticationendpoint/email-otp.jsp");

        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(claimMap);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        AuthenticatorConfig skipResendConfig = setAuthenticatorConfig();
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(skipResendConfig);
        when(CaptchaDataHolder.getInstance()).thenReturn(captchaDataHolder);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(identityConfigParser.getConfiguration()).thenReturn(new HashMap<>());

        Method skipResendMethod = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("initiateAuthenticationRequest",
                        HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class);
        skipResendMethod.setAccessible(true);
        try {
            skipResendMethod.invoke(emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
        } catch (InvocationTargetException ignored) {
        }

        // When skip=true user-based blocking is bypassed → OTP is sent → redirect to OTP page
        Assert.assertTrue(
                Boolean.parseBoolean(
                        String.valueOf(context.getProperty(AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP))),
                "OTP page redirect should happen when skipResendBlockTime=true bypasses user-based blocking.");
    }

    // -------------------------------------------------------------------------
    // Context-based retry limit control tests
    // -------------------------------------------------------------------------

    @DataProvider(name = "contextRetryLimitDataProvider")
    public Object[][] contextRetryLimitDataProvider() {

        // currentContextRetryAttempts (before this submission), maxAllowed, expectRetryLimitExceeded
        return new Object[][]{
                {0, 3, false},  // First failure — after increment becomes 1, still within limit
                {2, 3, true},   // Third failure — after increment becomes 3, equals limit → blocked
                {3, 3, true},   // Fourth failure — after increment becomes 4, exceeds limit
                {5, 3, true},   // Well past limit
        };
    }

    @Test(dataProvider = "contextRetryLimitDataProvider",
            description = "Test context-based retry limit: when OTP_RETRY_ATTEMPTS reaches the runtime-param "
                    + "limit the SKIP_RETRY_FROM_AUTHENTICATOR flag must be set in context.")
    public void testContextBasedRetryLimitBlocking(int currentRetryAttempts, int maxAllowed,
                                                   boolean expectRetryLimitSignalled) throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);

        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);
        // Simulate a wrong OTP stored in context
        context.setProperty(AuthenticatorConstants.OTP_TOKEN, "999999");
        context.setProperty(AuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        context.setProperty(AuthenticatorConstants.OTP_EXPIRED, Boolean.toString(false));
        // Pre-set retry counter
        context.setProperty(OTP_RETRY_ATTEMPTS, currentRetryAttempts);

        // Submit a wrong OTP
        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn(null);
        when(httpServletRequest.getParameter(CODE)).thenReturn("000000");
        when(httpServletRequest.getParameterNames()).thenReturn(
                Collections.enumeration(Collections.singletonList(CODE)));

        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(maxAllowed);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.isAccountLocked(any()))
                .thenReturn(false);

        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(new HashMap<>());

        Method method = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("processAuthenticationResponse",
                        HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class);
        method.setAccessible(true);

        try {
            method.invoke(emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
        } catch (InvocationTargetException ignored) {
            // OTP_INVALID or OTP_EXPIRED exception is expected
        }

        if (expectRetryLimitSignalled) {
            Assert.assertEquals(context.getProperty(SKIP_RETRY_FROM_AUTHENTICATOR), true,
                    "SKIP_RETRY_FROM_AUTHENTICATOR should be set when retry limit is exceeded.");
            Assert.assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                    FrameworkConstants.ERROR_STATUS_ALLOWED_RETRY_LIMIT_EXCEEDED,
                    "AUTH_ERROR_CODE should signal retry limit exceeded.");
        } else {
            Assert.assertNotEquals(context.getProperty(SKIP_RETRY_FROM_AUTHENTICATOR),
                    Boolean.TRUE,
                    "SKIP_RETRY_FROM_AUTHENTICATOR should NOT be set when retry limit is not reached.");
        }
    }

    @Test(description = "Test that OTP_RETRY_ATTEMPTS counter is incremented on each failed OTP submission.")
    public void testContextRetryCounterIncrement() throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);

        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);
        context.setProperty(AuthenticatorConstants.OTP_TOKEN, "999999");
        context.setProperty(AuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        context.setProperty(AuthenticatorConstants.OTP_EXPIRED, Boolean.toString(false));
        context.setProperty(OTP_RETRY_ATTEMPTS, 1);

        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn(null);
        when(httpServletRequest.getParameter(CODE)).thenReturn("000000");
        when(httpServletRequest.getParameterNames()).thenReturn(
                Collections.enumeration(Collections.singletonList(CODE)));

        // Retry limit disabled
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(-1);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.isAccountLocked(any()))
                .thenReturn(false);

        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(new HashMap<>());

        Method method = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("processAuthenticationResponse",
                        HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class);
        method.setAccessible(true);

        try {
            method.invoke(emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
        } catch (InvocationTargetException ignored) {
        }

        // Counter must have been incremented 1 → 2
        Assert.assertEquals(context.getProperty(OTP_RETRY_ATTEMPTS), 2,
                "OTP_RETRY_ATTEMPTS context counter should be incremented after a failed OTP submission.");
    }

    @Test(description = "Test that OTP_RETRY_ATTEMPTS and OTP_RESEND_ATTEMPTS context counters are reset "
            + "to 0 on successful OTP verification.")
    public void testContextCountersResetOnSuccess() throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);

        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);

        String correctOtp = "123456";
        context.setProperty(AuthenticatorConstants.OTP_TOKEN, correctOtp);
        context.setProperty(AuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        context.setProperty(AuthenticatorConstants.OTP_EXPIRED, Boolean.toString(false));
        // Simulate some prior attempts
        context.setProperty(OTP_RETRY_ATTEMPTS, 2);
        context.setProperty(OTP_RESEND_ATTEMPTS, 1);

        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn(null);
        when(httpServletRequest.getParameter(CODE)).thenReturn(correctOtp);
        when(httpServletRequest.getParameterNames()).thenReturn(
                Collections.enumeration(Collections.singletonList(CODE)));

        authenticatorUtils.when(() ->
                AuthenticatorUtils.isAccountLocked(any()))
                .thenReturn(false);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(-1);
        // Required by isOtpExpired -> getOtpValidityPeriod
        commonUtils.when(() -> CommonUtils.getOtpValidityPeriod(TENANT_DOMAIN))
                .thenReturn(300000L);

        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(new HashMap<>());
        // Allow resetOtpFailedAttempts and publishPostEmailOTPValidatedEvent events to go through
        Mockito.doNothing().when(identityEventService).handleEvent(any());

        Method resetCountersMethod = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("processAuthenticationResponse",
                        HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class);
        resetCountersMethod.setAccessible(true);
        try {
            resetCountersMethod.invoke(emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
        } catch (InvocationTargetException e) {
            Assert.fail("processAuthenticationResponse threw unexpectedly: " + e.getCause());
        }

        Assert.assertEquals(context.getProperty(OTP_RETRY_ATTEMPTS), 0,
                "OTP_RETRY_ATTEMPTS should be reset to 0 on successful authentication.");
        Assert.assertEquals(context.getProperty(OTP_RESEND_ATTEMPTS), 0,
                "OTP_RESEND_ATTEMPTS should be reset to 0 on successful authentication.");
    }

    @DataProvider(name = "remainingAttemptsDataProvider")
    public Object[][] remainingAttemptsDataProvider() {

        // maxAccountLockAttempts, currentFailedAttempts, maxContextRetryAttempts,
        // currentContextRetryAttempts, expectedRemaining
        return new Object[][]{
                // Context-based limit disabled (-1) → only account-lock based (5 - 2 = 3)
                {5, 2, -1, 0, 3},
                // Context-based limit enabled and more restrictive → min(3, 1) = 1
                {5, 2, 3, 2, 1},
                // Context-based limit enabled but less restrictive → min(3, 5) = 3
                {5, 2, 10, 5, 3},
                // Both give same value
                {5, 2, 3, 0, 3},
        };
    }

    @Test(dataProvider = "remainingAttemptsDataProvider",
            description = "Test getRemainingNumberOfOtpAttempts returns the minimum of account-lock-based "
                    + "and context-based remaining attempts when context-based retry blocking is enabled.")
    public void testGetRemainingNumberOfOtpAttempts(int maxAccountLockAttempts, int currentFailedAttempts,
                                                    int maxContextRetryAttempts, int currentContextRetryAttempts,
                                                    int expectedRemaining) throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);

        context.setTenantDomain(TENANT_DOMAIN);
        context.setProperty(OTP_RETRY_ATTEMPTS, currentContextRetryAttempts);

        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(AuthenticatorConstants.Claims.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM,
                String.valueOf(currentFailedAttempts));

        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(claimMap);

        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(maxContextRetryAttempts);

        org.wso2.carbon.identity.application.common.model.Property failedLoginProp =
                new org.wso2.carbon.identity.application.common.model.Property();
        failedLoginProp.setName("account.lock.handler.On.Failure.Max.Attempts");
        failedLoginProp.setValue(String.valueOf(maxAccountLockAttempts));
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getAccountLockConnectorConfigs(TENANT_DOMAIN))
                .thenReturn(new org.wso2.carbon.identity.application.common.model.Property[]{failedLoginProp});

        Method method = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("getRemainingNumberOfOtpAttempts",
                        String.class, AuthenticationContext.class);
        method.setAccessible(true);
        int result = (int) method.invoke(emailOTPAuthenticator, TENANT_DOMAIN, context);

        Assert.assertEquals(result, expectedRemaining,
                "Remaining OTP attempts should be the minimum of account-lock based and context-based limits.");
    }

    // -------------------------------------------------------------------------
    // Combined user-based + context-based resend blocking tests
    // -------------------------------------------------------------------------

    @Test(description = "Test that context-based resend blocking is applied alongside user-based blocking: "
            + "context counter is NOT updated when user-based blocking alone is active.")
    public void testContextCounterNotIncrementedWhenOnlyUserBasedBlockingActive() throws Exception {

        setAuthenticatorConfig();
        configureAuthenticatorDataHolder();
        configureAuthenticatedUser(false);

        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);
        context.setProperty(OTP_RESEND_ATTEMPTS, 0);

        when(httpServletRequest.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");

        // User-based blocking enabled (max = 5), context-based disabled (-1)
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_RESEND_ATTEMPTS_COUNT, TENANT_DOMAIN))
                .thenReturn("5");
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getSkipResendBlockTimeParam(any()))
                .thenReturn("false");
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedResendAttemptsLimit(any()))
                .thenReturn(-1);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getMaximumAllowedRetryAttemptsLimit(any()))
                .thenReturn(-1);
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailOTPLoginPageUrl(any(), anyString()))
                .thenReturn("https://localhost:9443/authenticationendpoint/email-otp.jsp");
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_RESEND_BLOCK_DURATION, TENANT_DOMAIN))
                .thenReturn("5");

        Map<String, String> claimMap = new HashMap<>();
        // Below user-based max so OTP is sent
        claimMap.put(EMAIL_OTP_RESEND_ATTEMPTS_CLAIM, "1");
        claimMap.put(EMAIL_OTP_LAST_SENT_TIME_CLAIM,
                String.valueOf(System.currentTimeMillis() - 10 * 60_000L)); // 10 min ago → outside block window

        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(claimMap);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        AuthenticatorConfig userBasedOnlyConfig = setAuthenticatorConfig();
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(userBasedOnlyConfig);
        when(CaptchaDataHolder.getInstance()).thenReturn(captchaDataHolder);
        when(IdentityConfigParser.getInstance()).thenReturn(identityConfigParser);
        when(identityConfigParser.getConfiguration()).thenReturn(new HashMap<>());

        Method userBasedOnlyMethod = emailOTPAuthenticator.getClass()
                .getDeclaredMethod("initiateAuthenticationRequest",
                        HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class);
        userBasedOnlyMethod.setAccessible(true);
        try {
            userBasedOnlyMethod.invoke(emailOTPAuthenticator, httpServletRequest, httpServletResponse, context);
        } catch (InvocationTargetException ignored) {
        }

        // Context counter should remain 0 — only user-based blocking is active
        Assert.assertEquals(context.getProperty(OTP_RESEND_ATTEMPTS), 0,
                "Context resend counter should NOT be incremented when only user-based blocking is active.");
    }
}
