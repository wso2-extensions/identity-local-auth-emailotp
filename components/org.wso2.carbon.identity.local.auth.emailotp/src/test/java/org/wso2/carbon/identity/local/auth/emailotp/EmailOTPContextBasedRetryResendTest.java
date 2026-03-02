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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceDataHolder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.emailotp.util.AuthenticatorUtils;
import org.wso2.carbon.identity.local.auth.emailotp.util.CommonUtils;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.Claims.EMAIL_OTP_LAST_SENT_TIME_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.Claims.EMAIL_OTP_RESEND_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.MAXIMUM_ALLOWED_FAILURE_LIMIT;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.MAXIMUM_RESEND_LIMIT;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.SKIP_RESEND_BLOCK_TIME;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.TERMINATE_ON_RESEND_LIMIT_EXCEEDED;

/**
 * Test cases for context-based retry/resend control logic in EmailOTPAuthenticator.
 * Covers both flow-level behaviour (initiateAuthenticationRequest, processAuthenticationResponse)
 * and individual method behaviour.
 */
public class EmailOTPContextBasedRetryResendTest {

    private static final String USERNAME = "user@wso2.com";
    private static final String USER_ID = "47f02f57-a6a1-4677-8de1-8cfe31b42456";
    private static final String EMAIL_ADDRESS = "user@wso2.com";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String USER_STORE_DOMAIN = "PRIMARY";
    private static final String DEFAULT_USER_STORE = "DEFAULT";
    private static final String DUMMY_LOGIN_PAGE_URL = "https://localhost:9443/authenticationendpoint/login.do";

    private EmailOTPAuthenticator emailOTPAuthenticator;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private AuthenticationContext context;
    private ConfigurationFacade configurationFacade;
    private FileBasedConfigurationBuilder fileBasedConfigurationBuilder;
    private FrameworkServiceDataHolder frameworkServiceDataHolder;
    private RealmService realmService;
    private UserRealm userRealm;
    private AbstractUserStoreManager userStoreManager;
    private MultiAttributeLoginService multiAttributeLoginService;

    private MockedStatic<ConfigurationFacade> staticConfigurationFacade;
    private MockedStatic<FrameworkUtils> frameworkUtils;
    private MockedStatic<FileBasedConfigurationBuilder> staticFileBasedConfigurationBuilder;
    private MockedStatic<FrameworkServiceDataHolder> staticFrameworkServiceDataHolder;
    private MockedStatic<AuthenticatorUtils> authenticatorUtils;
    private MockedStatic<CommonUtils> commonUtils;
    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<UserCoreUtil> userCoreUtil;
    private MockedStatic<IdentityTenantUtil> identityTenantUtil;

    @BeforeMethod
    public void setUp() {
        emailOTPAuthenticator = new TestEmailOTPAuthenticator();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        context = new AuthenticationContext();
        configurationFacade = mock(ConfigurationFacade.class);
        fileBasedConfigurationBuilder = mock(FileBasedConfigurationBuilder.class);
        frameworkServiceDataHolder = mock(FrameworkServiceDataHolder.class);
        realmService = mock(RealmService.class);
        userRealm = mock(UserRealm.class);
        userStoreManager = mock(AbstractUserStoreManager.class);
        multiAttributeLoginService = mock(MultiAttributeLoginService.class);

        staticConfigurationFacade = mockStatic(ConfigurationFacade.class);
        frameworkUtils = mockStatic(FrameworkUtils.class);
        staticFileBasedConfigurationBuilder = mockStatic(FileBasedConfigurationBuilder.class);
        staticFrameworkServiceDataHolder = mockStatic(FrameworkServiceDataHolder.class);
        authenticatorUtils = mockStatic(AuthenticatorUtils.class);
        commonUtils = mockStatic(CommonUtils.class);
        loggerUtils = mockStatic(LoggerUtils.class);
        userCoreUtil = mockStatic(UserCoreUtil.class, Mockito.CALLS_REAL_METHODS);
        identityTenantUtil = mockStatic(IdentityTenantUtil.class);

        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        identityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(-1234);
        when(frameworkServiceDataHolder.getMultiAttributeLoginService()).thenReturn(multiAttributeLoginService);
        when(multiAttributeLoginService.isEnabled(anyString())).thenReturn(false);
        authenticatorUtils.when(() -> AuthenticatorUtils.getOptionalParamFromRuntimeParams(any(), anyString()))
                .thenCallRealMethod();
        authenticatorUtils.when(() -> AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(any(), anyString()))
                .thenCallRealMethod();
        authenticatorUtils.when(() -> AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(any(), anyString()))
                .thenCallRealMethod();
        AuthenticatorDataHolder.setIdentityEventService(mock(IdentityEventService.class));
    }

    @AfterMethod
    public void tearDown() {
        if (staticConfigurationFacade != null) {
            staticConfigurationFacade.close();
        }
        if (frameworkUtils != null) {
            frameworkUtils.close();
        }
        if (staticFileBasedConfigurationBuilder != null) {
            staticFileBasedConfigurationBuilder.close();
        }
        if (staticFrameworkServiceDataHolder != null) {
            staticFrameworkServiceDataHolder.close();
        }
        if (authenticatorUtils != null) {
            authenticatorUtils.close();
        }
        if (commonUtils != null) {
            commonUtils.close();
        }
        if (loggerUtils != null) {
            loggerUtils.close();
        }
        if (userCoreUtil != null) {
            userCoreUtil.close();
        }
        if (identityTenantUtil != null) {
            identityTenantUtil.close();
        }
    }

    // --------------------------- Flow tests: initiateAuthenticationRequest (resend limit) ---------------------------

    @Test(description = "Flow: initiateAuthenticationRequest with context-based resend limit exceeded " +
            "enforces resend limit and does not redirect to email OTP page")
    public void testInitiateAuthenticationRequest_ContextResendLimitExceeded_EnforcesLimit() throws Exception {
        // Context-based resend: max 2, current already 2; terminate so we get AUTH_ERROR_CODE set
        Map<String, String> params = new HashMap<>();
        params.put(MAXIMUM_RESEND_LIMIT, "2");
        params.put(TERMINATE_ON_RESEND_LIMIT_EXCEEDED, "true");
        addRuntimeParamsToContext(params);
        context.setProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);

        when(request.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");
        when(request.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(USERNAME);

        setStepConfigWithEmailOTPAuthenticator(context);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(FrameworkServiceDataHolder.getInstance()).thenReturn(frameworkServiceDataHolder);
        when(frameworkServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        // User exists so we go past null-user branch; then email is resolved
        AuthenticatedUser subject = new AuthenticatedUser();
        subject.setUserName(USERNAME);
        subject.setTenantDomain(TENANT_DOMAIN);
        subject.setUserStoreDomain(USER_STORE_DOMAIN);
        subject.setUserId(USER_ID);
        context.setSubject(subject);

        User user = new User(UUID.randomUUID().toString(), USERNAME, null);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(TENANT_DOMAIN);
        List<User> userList = new ArrayList<>();
        userList.add(user);
        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EMAIL_ADDRESS_CLAIM, EMAIL_ADDRESS);
        claimMap.put(EMAIL_OTP_RESEND_ATTEMPTS_CLAIM, "0");
        claimMap.put(EMAIL_OTP_LAST_SENT_TIME_CLAIM, String.valueOf(System.currentTimeMillis()));

        when(userStoreManager.getUserListWithID(USERNAME_CLAIM, USERNAME, null)).thenReturn(userList);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(claimMap);
        when(userStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(userStoreManager);
        userCoreUtil.when(() -> UserCoreUtil.getDomainFromThreadLocal()).thenReturn(DEFAULT_USER_STORE);

        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_RESEND_ATTEMPTS_COUNT,
                        TENANT_DOMAIN)).thenReturn("5");
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailOTPLoginPageUrl(any(), anyString())).thenReturn(DUMMY_LOGIN_PAGE_URL);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString()))
                .thenReturn(getAuthenticatorConfig());
        commonUtils.when(() -> CommonUtils.maskIfRequired(anyString())).thenAnswer(inv -> inv.getArgument(0));
        AuthenticatorDataHolder.setRealmService(realmService);

        Method method = findMethod(EmailOTPAuthenticator.class, "initiateAuthenticationRequest",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class});

        try {
            method.invoke(emailOTPAuthenticator, request, response, context);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof AuthenticationFailedException) {
                // terminate path: AUTH_ERROR_CODE should already be set
            } else {
                throw e;
            }
        }

        Object authErrorCode = context.getProperty(FrameworkConstants.AUTH_ERROR_CODE);
        Object redirectToOtp = context.getProperty(AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP);
        Assert.assertEquals(authErrorCode, FrameworkConstants.ERROR_STATUS_ALLOWED_RESEND_LIMIT_EXCEEDED,
                "Resend limit exceeded should set AUTH_ERROR_CODE when terminate is true");
        Assert.assertNull(redirectToOtp, "Should not redirect to OTP page when resend limit exceeded");
    }

    @Test(description = "Flow: initiateAuthenticationRequest with context-based resend under limit " +
            "allows resend and updates context resend count")
    public void testInitiateAuthenticationRequest_ContextResendUnderLimit_UpdatesResendCount() throws Exception {
        addRuntimeParamsToContext(MAXIMUM_RESEND_LIMIT, "5");
        context.setTenantDomain(TENANT_DOMAIN);
        context.setRetrying(true);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);

        when(request.getParameter(AuthenticatorConstants.RESEND)).thenReturn("true");
        when(request.getParameter(AuthenticatorConstants.USER_NAME)).thenReturn(USERNAME);

        setStepConfigWithEmailOTPAuthenticator(context);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(DUMMY_LOGIN_PAGE_URL);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(FrameworkServiceDataHolder.getInstance()).thenReturn(frameworkServiceDataHolder);
        when(frameworkServiceDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);

        AuthenticatedUser subject = new AuthenticatedUser();
        subject.setUserName(USERNAME);
        subject.setTenantDomain(TENANT_DOMAIN);
        subject.setUserStoreDomain(USER_STORE_DOMAIN);
        subject.setUserId(USER_ID);
        context.setSubject(subject);

        User user = new User(UUID.randomUUID().toString(), USERNAME, null);
        user.setUserStoreDomain(USER_STORE_DOMAIN);
        user.setTenantDomain(TENANT_DOMAIN);
        List<User> userList = new ArrayList<>();
        userList.add(user);
        Map<String, String> claimMap = new HashMap<>();
        claimMap.put(EMAIL_ADDRESS_CLAIM, EMAIL_ADDRESS);
        claimMap.put(EMAIL_OTP_RESEND_ATTEMPTS_CLAIM, "0");
        claimMap.put(EMAIL_OTP_LAST_SENT_TIME_CLAIM, String.valueOf(System.currentTimeMillis()));

        when(userStoreManager.getUserListWithID(USERNAME_CLAIM, USERNAME, null)).thenReturn(userList);
        when(userStoreManager.getUserClaimValues(any(), any(), any())).thenReturn(claimMap);
        when(userStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(userStoreManager);
        userCoreUtil.when(() -> UserCoreUtil.getDomainFromThreadLocal()).thenReturn(DEFAULT_USER_STORE);

        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_RESEND_ATTEMPTS_COUNT,
                        TENANT_DOMAIN)).thenReturn("5");
        authenticatorUtils.when(() ->
                AuthenticatorUtils.getEmailOTPLoginPageUrl(any(), anyString())).thenReturn(DUMMY_LOGIN_PAGE_URL);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString()))
                .thenReturn(getAuthenticatorConfig());
        AuthenticatorDataHolder.setRealmService(realmService);

        Method method = findMethod(EmailOTPAuthenticator.class, "initiateAuthenticationRequest",
                new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class});

        try {
            method.invoke(emailOTPAuthenticator, request, response, context);
        } catch (InvocationTargetException ignored) {
        }

        // Resend count should have been incremented (RESEND_OTP scenario)
        Object resendCount = context.getProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME);
        assertNotNull(resendCount, "Context resend count should be updated when resend is under limit");
        assertEquals(((Number) resendCount).intValue(), 1, "Resend count should be 1 after one resend");
    }

    // --------------------------- Flow tests: processAuthenticationResponse (retry limit) ---------------------------

    @Test(description = "Flow: processAuthenticationResponse with context-based retry limit " +
            "increments retry count on invalid OTP")
    public void testProcessAuthenticationResponse_ContextRetry_IncrementsCountOnInvalidOtp() throws Exception {
        addRuntimeParamsToContext(MAXIMUM_ALLOWED_FAILURE_LIMIT, "3");
        context.setTenantDomain(TENANT_DOMAIN);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);
        setStepConfigWithEmailOTPAuthenticator(context);

        AuthenticatedUser subject = new AuthenticatedUser();
        subject.setUserName(USERNAME);
        subject.setTenantDomain(TENANT_DOMAIN);
        subject.setUserStoreDomain(USER_STORE_DOMAIN);
        subject.setUserId(USER_ID);
        context.setSubject(subject);

        when(request.getParameter(AuthenticatorConstants.CODE)).thenReturn("000000");
        when(request.getParameter(AuthenticatorConstants.RESEND)).thenReturn(null);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString()))
                .thenReturn(getAuthenticatorConfig());
        context.setProperty(AuthenticatorConstants.OTP_TOKEN, "123456");
        context.setProperty(AuthenticatorConstants.OTP_EXPIRED, "false");
        context.setProperty(AuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        commonUtils.when(() -> CommonUtils.getOtpValidityPeriod(TENANT_DOMAIN)).thenReturn(300000L);

        authenticatorUtils.when(() -> AuthenticatorUtils.isAccountLocked(any())).thenReturn(false);

        try {
            emailOTPAuthenticator.processAuthenticationResponse(request, response, context);
        } catch (AuthenticationFailedException ignored) {
        }

        Object retryCount = context.getProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME);
        assertNotNull(retryCount, "Retry count should be updated on invalid OTP when context retry is enabled");
        assertEquals(((Number) retryCount).intValue(), 1, "Retry count should be 1 after one failed attempt");
    }

    @Test(description = "Flow: processAuthenticationResponse when retry limit exceeded sets AUTH_ERROR_CODE" +
            " and SKIP_RETRY")
    public void testProcessAuthenticationResponse_RetryLimitExceeded_SetsErrorCodeAndSkipRetry() throws Exception {
        addRuntimeParamsToContext(MAXIMUM_ALLOWED_FAILURE_LIMIT, "2");
        context.setProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1); // one more failure will hit limit
        context.setTenantDomain(TENANT_DOMAIN);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);
        setStepConfigWithEmailOTPAuthenticator(context);

        AuthenticatedUser subject = new AuthenticatedUser();
        subject.setUserName(USERNAME);
        subject.setTenantDomain(TENANT_DOMAIN);
        subject.setUserStoreDomain(USER_STORE_DOMAIN);
        subject.setUserId(USER_ID);
        context.setSubject(subject);

        when(request.getParameter(AuthenticatorConstants.CODE)).thenReturn("000000");
        when(request.getParameter(AuthenticatorConstants.RESEND)).thenReturn(null);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString()))
                .thenReturn(getAuthenticatorConfig());
        context.setProperty(AuthenticatorConstants.OTP_TOKEN, "123456");
        context.setProperty(AuthenticatorConstants.OTP_EXPIRED, "false");
        context.setProperty(AuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        commonUtils.when(() -> CommonUtils.getOtpValidityPeriod(TENANT_DOMAIN)).thenReturn(300000L);

        authenticatorUtils.when(() -> AuthenticatorUtils.isAccountLocked(any())).thenReturn(false);

        try {
            emailOTPAuthenticator.processAuthenticationResponse(request, response, context);
        } catch (AuthenticationFailedException ignored) {
        }

        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                FrameworkConstants.ERROR_STATUS_ALLOWED_RETRY_LIMIT_EXCEEDED,
                "AUTH_ERROR_CODE should be set when retry limit exceeded");
        assertEquals(context.getProperty(AbstractApplicationAuthenticator.SKIP_RETRY_FROM_AUTHENTICATOR), true,
                "SKIP_RETRY_FROM_AUTHENTICATOR should be set when retry limit exceeded");
    }

    @Test(description = "Flow: processAuthenticationResponse on successful OTP resets context retry and resend counts")
    public void testProcessAuthenticationResponse_Success_ResetsContextRetryAndResendCounts() throws Exception {
        context.setProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1);
        context.setProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1);
        context.setTenantDomain(TENANT_DOMAIN);
        context.setCurrentAuthenticator(EMAIL_OTP_AUTHENTICATOR_NAME);
        setStepConfigWithEmailOTPAuthenticator(context);

        AuthenticatedUser subject = new AuthenticatedUser();
        subject.setUserName(USERNAME);
        subject.setTenantDomain(TENANT_DOMAIN);
        subject.setUserStoreDomain(USER_STORE_DOMAIN);
        subject.setUserId(USER_ID);
        context.setSubject(subject);

        when(request.getParameter(AuthenticatorConstants.CODE)).thenReturn("123456");
        when(request.getParameter(AuthenticatorConstants.RESEND)).thenReturn(null);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(anyString()))
                .thenReturn(getAuthenticatorConfig());
        context.setProperty(AuthenticatorConstants.OTP_TOKEN, "123456");
        context.setProperty(AuthenticatorConstants.OTP_EXPIRED, "false");
        context.setProperty(AuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());

        authenticatorUtils.when(() -> AuthenticatorUtils.isAccountLocked(any())).thenReturn(false);
        commonUtils.when(() -> CommonUtils.getOtpValidityPeriod(TENANT_DOMAIN)).thenReturn(300000L);

        emailOTPAuthenticator.processAuthenticationResponse(request, response, context);

        assertEquals(context.getProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 0,
                "Retry count should be reset on success");
        assertEquals(context.getProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME), 0,
                "Resend count should be reset on success");
    }

    // --------------------------- Individual method tests (protected) ---------------------------

    @Test(description = "isContextBasedOTPResendBlockingEnabled returns true when MAXIMUM_RESEND_LIMIT is set and >= 0")
    public void testIsContextBasedOTPResendBlockingEnabled_WithValidLimit() throws AuthenticationFailedException {
        addRuntimeParamsToContext(MAXIMUM_RESEND_LIMIT, "3");
        Assert.assertTrue(emailOTPAuthenticator.isContextBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "isContextBasedOTPResendBlockingEnabled returns true when limit is 0")
    public void testIsContextBasedOTPResendBlockingEnabled_WithZeroLimit() throws AuthenticationFailedException {
        addRuntimeParamsToContext(MAXIMUM_RESEND_LIMIT, "0");
        Assert.assertTrue(emailOTPAuthenticator.isContextBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "isContextBasedOTPResendBlockingEnabled returns false when param absent")
    public void testIsContextBasedOTPResendBlockingEnabled_WithNoParam() throws AuthenticationFailedException {
        Assert.assertFalse(emailOTPAuthenticator.isContextBasedOTPResendBlockingEnabled(context));
    }

    @Test(description = "isContextBasedRetryBlockingEnabled returns true when MAXIMUM_ALLOWED_FAILURE_LIMIT " +
            "is positive")
    public void testIsContextBasedRetryBlockingEnabled_WithPositiveLimit() throws AuthenticationFailedException {
        addRuntimeParamsToContext(MAXIMUM_ALLOWED_FAILURE_LIMIT, "5");
        Assert.assertTrue(emailOTPAuthenticator.isContextBasedRetryBlockingEnabled(context));
    }

    @Test(description = "isContextBasedRetryBlockingEnabled returns false when limit is 0")
    public void testIsContextBasedRetryBlockingEnabled_WithZeroLimit() throws AuthenticationFailedException {
        addRuntimeParamsToContext(MAXIMUM_ALLOWED_FAILURE_LIMIT, "0");
        Assert.assertFalse(emailOTPAuthenticator.isContextBasedRetryBlockingEnabled(context));
    }

    @Test(description = "isContextBasedRetryBlockingEnabled returns false when param absent")
    public void testIsContextBasedRetryBlockingEnabled_WithNoParam() throws AuthenticationFailedException {
        Assert.assertFalse(emailOTPAuthenticator.isContextBasedRetryBlockingEnabled(context));
    }

    @Test(description = "isTerminateOnResendLimitExceeded returns true when param is true")
    public void testIsTerminateOnResendLimitExceeded_WhenTrue() throws AuthenticationFailedException {
        addRuntimeParamsToContext(TERMINATE_ON_RESEND_LIMIT_EXCEEDED, "true");
        Assert.assertTrue(emailOTPAuthenticator.isTerminateOnResendLimitExceeded(context));
    }

    @Test(description = "isTerminateOnResendLimitExceeded returns false when param is false")
    public void testIsTerminateOnResendLimitExceeded_WhenFalse() throws AuthenticationFailedException {
        addRuntimeParamsToContext(TERMINATE_ON_RESEND_LIMIT_EXCEEDED, "false");
        Assert.assertFalse(emailOTPAuthenticator.isTerminateOnResendLimitExceeded(context));
    }

    @Test(description = "isUserBasedOTPResendBlockingEnabled returns false when skipResendBlockTime is true")
    public void testIsUserBasedOTPResendBlockingEnabled_SkipResendBlockTimeTrue() throws AuthenticationFailedException {
        addRuntimeParamsToContext(SKIP_RESEND_BLOCK_TIME, "true");
        Assert.assertFalse(emailOTPAuthenticator.isUserBasedOTPResendBlockingEnabled(TENANT_DOMAIN, context));
    }

    // --------------------------- Individual method tests (private, via reflection) ---------------------------

    @Test(description = "getMaximumResendAttemptsFromContext returns runtime param when set")
    public void testGetMaximumResendAttemptsFromContext_WithParam() throws Exception {
        addRuntimeParamsToContext(MAXIMUM_RESEND_LIMIT, "7");
        int result = invokePrivateIntMethod("getMaximumResendAttemptsFromContext",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(result, 7);
    }

    @Test(description = "getMaximumResendAttemptsFromContext returns Integer.MAX_VALUE when param absent")
    public void testGetMaximumResendAttemptsFromContext_NoParam() throws Exception {
        int result = invokePrivateIntMethod("getMaximumResendAttemptsFromContext",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(result, Integer.MAX_VALUE);
    }

    @Test(description = "getMaximumRetryAttempts returns runtime param when context retry enabled")
    public void testGetMaximumRetryAttempts_WithContextParam() throws Exception {
        addRuntimeParamsToContext(MAXIMUM_ALLOWED_FAILURE_LIMIT, "4");
        int result = invokePrivateIntMethod("getMaximumRetryAttempts",
                new Class[]{String.class, AuthenticationContext.class},
                new Object[]{TENANT_DOMAIN, context});
        assertEquals(result, 4);
    }

    @Test(description = "getMaximumRetryAttempts returns Integer.MAX_VALUE when context retry disabled")
    public void testGetMaximumRetryAttempts_NoContextParam() throws Exception {
        int result = invokePrivateIntMethod("getMaximumRetryAttempts",
                new Class[]{String.class, AuthenticationContext.class},
                new Object[]{TENANT_DOMAIN, context});
        assertEquals(result, Integer.MAX_VALUE);
    }

    @Test(description = "isOTPResendLimitExceeded returns true when current >= limit")
    public void testIsOTPResendLimitExceeded_WhenAtOrOverLimit() throws Exception {
        addRuntimeParamsToContext(MAXIMUM_RESEND_LIMIT, "2");
        context.setProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        boolean result = invokePrivateBooleanMethod("isOTPResendLimitExceeded",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});
        Assert.assertTrue(result);
    }

    @Test(description = "isOTPResendLimitExceeded returns false when current below limit")
    public void testIsOTPResendLimitExceeded_WhenBelowLimit() throws Exception {
        addRuntimeParamsToContext(MAXIMUM_RESEND_LIMIT, "5");
        context.setProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        boolean result = invokePrivateBooleanMethod("isOTPResendLimitExceeded",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});
        Assert.assertFalse(result);
    }

    @DataProvider(name = "resendScenarioProvider")
    public Object[][] resendScenarioProvider() {
        return new Object[][]{
                {AuthenticatorConstants.AuthenticationScenarios.RESEND_OTP, true},
                {AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP, false},
                {AuthenticatorConstants.AuthenticationScenarios.SUBMIT_OTP, false},
        };
    }

    @Test(dataProvider = "resendScenarioProvider",
            description = "isOTPResendLimitExceededScenario returns true only for RESEND_OTP when limit exceeded")
    public void testIsOTPResendLimitExceededScenario(AuthenticatorConstants.AuthenticationScenarios scenario,
                                                      boolean expectTrueWhenLimitExceeded) throws Exception {
        addRuntimeParamsToContext(MAXIMUM_RESEND_LIMIT, "1");
        context.setProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1);
        context.setTenantDomain(TENANT_DOMAIN);
        boolean result = invokePrivateBooleanMethod("isOTPResendLimitExceededScenario",
                new Class[]{AuthenticatorConstants.AuthenticationScenarios.class, AuthenticationContext.class},
                new Object[]{scenario, context});
        if (expectTrueWhenLimitExceeded) {
            Assert.assertTrue(result, "RESEND_OTP with limit exceeded should return true");
        } else {
            Assert.assertFalse(result);
        }
    }

    @Test(description = "updateContextOTPResendCount initialises to 1 when not set")
    public void testUpdateContextOTPResendCount_InitialisesToOne() throws Exception {
        invokePrivateVoidMethod("updateContextOTPResendCount",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(context.getProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME), 1);
    }

    @Test(description = "updateContextOTPResendCount increments when already set")
    public void testUpdateContextOTPResendCount_Increments() throws Exception {
        context.setProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        invokePrivateVoidMethod("updateContextOTPResendCount",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(context.getProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME), 3);
    }

    @Test(description = "updateContextOTPRetryCount initialises to 1 when not set")
    public void testUpdateContextOTPRetryCount_InitialisesToOne() throws Exception {
        invokePrivateVoidMethod("updateContextOTPRetryCount",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(context.getProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 1);
    }

    @Test(description = "updateContextOTPRetryCount increments when already set")
    public void testUpdateContextOTPRetryCount_Increments() throws Exception {
        context.setProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 3);
        invokePrivateVoidMethod("updateContextOTPRetryCount",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(context.getProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 4);
    }

    @Test(description = "resetContextRetryCount sets retry count to 0")
    public void testResetContextRetryCount() throws Exception {
        context.setProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 5);
        invokePrivateVoidMethod("resetContextRetryCount",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(context.getProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 0);
    }

    @Test(description = "resetContextResendCount sets resend count to 0")
    public void testResetContextResendCount() throws Exception {
        context.setProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 3);
        invokePrivateVoidMethod("resetContextResendCount",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(context.getProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME), 0);
    }

    @Test(description = "getCurrentRetryAttempt returns 0 when not set")
    public void testGetCurrentRetryAttempt_WhenNotSet() throws Exception {
        int result = invokePrivateIntMethod("getCurrentRetryAttempt",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(result, 0);
    }

    @Test(description = "getCurrentRetryAttempt returns stored value")
    public void testGetCurrentRetryAttempt_WhenSet() throws Exception {
        context.setProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 2);
        int result = invokePrivateIntMethod("getCurrentRetryAttempt",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(result, 2);
    }

    @Test(description = "getCurrentResendAttempt returns 0 when not set")
    public void testGetCurrentResendAttempt_WhenNotSet() throws Exception {
        int result = invokePrivateIntMethod("getCurrentResendAttempt",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(result, 0);
    }

    @Test(description = "getCurrentResendAttempt returns stored value")
    public void testGetCurrentResendAttempt_WhenSet() throws Exception {
        context.setProperty(EMAIL_OTP_RESEND_ATTEMPTS_CONTEXT_PROPERTY_NAME, 3);
        int result = invokePrivateIntMethod("getCurrentResendAttempt",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(result, 3);
    }

    @Test(description = "handleOTPRetryCountExceededScenario sets SKIP_RETRY and AUTH_ERROR_CODE")
    public void testHandleOTPRetryCountExceededScenario_SetsContextProperties() throws Exception {
        invokePrivateVoidMethod("handleOTPRetryCountExceededScenario",
                new Class[]{AuthenticationContext.class}, new Object[]{context});
        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                FrameworkConstants.ERROR_STATUS_ALLOWED_RETRY_LIMIT_EXCEEDED);
        assertEquals(context.getProperty(AbstractApplicationAuthenticator.SKIP_RETRY_FROM_AUTHENTICATOR), true);
    }

    @Test(description = "handleInvalidOTPLoginAttempt increments retry count when context retry enabled")
    public void testHandleInvalidOTPLoginAttempt_IncrementsRetryWhenEnabled() throws Exception {
        addRuntimeParamsToContext(MAXIMUM_ALLOWED_FAILURE_LIMIT, "5");
        invokePrivateVoidMethod("handleInvalidOTPLoginAttempt",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});
        assertEquals(context.getProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME), 1);
    }

    @Test(description = "handleInvalidOTPLoginAttempt does not increment when context retry disabled")
    public void testHandleInvalidOTPLoginAttempt_NoIncrementWhenDisabled() throws Exception {
        invokePrivateVoidMethod("handleInvalidOTPLoginAttempt",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});
        assertNull(context.getProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME));
    }

    @Test(description = "handleInvalidOTPLoginAttempt sets AUTH_ERROR_CODE when retry limit reached")
    public void testHandleInvalidOTPLoginAttempt_SetsErrorWhenLimitReached() throws Exception {
        addRuntimeParamsToContext(MAXIMUM_ALLOWED_FAILURE_LIMIT, "2");
        context.setProperty(EMAIL_OTP_RETRY_ATTEMPTS_CONTEXT_PROPERTY_NAME, 1);
        invokePrivateVoidMethod("handleInvalidOTPLoginAttempt",
                new Class[]{AuthenticationContext.class, String.class},
                new Object[]{context, TENANT_DOMAIN});
        assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                FrameworkConstants.ERROR_STATUS_ALLOWED_RETRY_LIMIT_EXCEEDED);
    }

    @Test(description = "handleOTPResendCountExceededScenario with terminateFlow=true and user throws and sets " +
            "AUTH_ERROR_CODE")
    public void testHandleOTPResendCountExceededScenario_TerminateFlowWithUser() throws Exception {
        context.setRetrying(true);
        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName("testuser");
        user.setTenantDomain(TENANT_DOMAIN);
        commonUtils.when(() -> CommonUtils.maskIfRequired(anyString())).thenReturn("testuser");

        try {
            invokePrivateVoidMethod("handleOTPResendCountExceededScenario",
                    new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class,
                            AuthenticatedUser.class, boolean.class},
                    new Object[]{request, response, context, user, true});
            Assert.fail("Expected AuthenticationFailedException");
        } catch (InvocationTargetException e) {
            Assert.assertTrue(e.getCause() instanceof AuthenticationFailedException);
            assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                    FrameworkConstants.ERROR_STATUS_ALLOWED_RESEND_LIMIT_EXCEEDED);
            Assert.assertFalse(context.isRetrying());
        }
    }

    @Test(description = "handleOTPResendCountExceededScenario with terminateFlow=true and null user throws with " +
            "UNKNOWN_USER")
    public void testHandleOTPResendCountExceededScenario_TerminateFlowWithNullUser() throws Exception {
        context.setRetrying(true);
        try {
            invokePrivateVoidMethod("handleOTPResendCountExceededScenario",
                    new Class[]{HttpServletRequest.class, HttpServletResponse.class, AuthenticationContext.class,
                            AuthenticatedUser.class, boolean.class},
                    new Object[]{request, response, context, null, true});
            Assert.fail("Expected AuthenticationFailedException");
        } catch (InvocationTargetException e) {
            Assert.assertTrue(e.getCause() instanceof AuthenticationFailedException);
            Assert.assertTrue(e.getCause().getMessage().contains("Unknown user"));
            assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE),
                    FrameworkConstants.ERROR_STATUS_ALLOWED_RESEND_LIMIT_EXCEEDED);
        }
    }

    // --------------------------- Helpers ---------------------------

    private void addRuntimeParamsToContext(String paramName, String paramValue) {
        Map<String, String> params = new HashMap<>();
        params.put(paramName, paramValue);
        addRuntimeParamsToContext(params);
    }

    private void addRuntimeParamsToContext(Map<String, String> params) {
        ((TestEmailOTPAuthenticator) emailOTPAuthenticator).setRuntimeParams(params != null ? params : new HashMap<>());
    }

    private void setStepConfigWithEmailOTPAuthenticator(AuthenticationContext ctx) {
        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        StepConfig step = new StepConfig();
        AuthenticatorConfig authConfig = getAuthenticatorConfig();
        authConfig.setName(EMAIL_OTP_AUTHENTICATOR_NAME);
        List<AuthenticatorConfig> list = new ArrayList<>();
        list.add(authConfig);
        step.setAuthenticatorList(list);
        step.setSubjectAttributeStep(true);
        stepConfigMap.put(1, step);
        SequenceConfig seq = new SequenceConfig();
        seq.setStepMap(stepConfigMap);
        ctx.setSequenceConfig(seq);
        ctx.setCurrentStep(1);
        ApplicationConfig appConfig = mock(ApplicationConfig.class);
        when(appConfig.isSaaSApp()).thenReturn(false);
        ctx.getSequenceConfig().setApplicationConfig(appConfig);
    }

    private AuthenticatorConfig getAuthenticatorConfig() {
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setParameterMap(new HashMap<>());
        config.setName(EMAIL_OTP_AUTHENTICATOR_NAME);
        return config;
    }

    private Method findMethod(Class<?> clazz, String name, Class<?>[] paramTypes) throws NoSuchMethodException {
        try {
            Method m = clazz.getDeclaredMethod(name, paramTypes);
            m.setAccessible(true);
            return m;
        } catch (NoSuchMethodException e) {
            if (clazz.getSuperclass() != null) {
                return findMethod(clazz.getSuperclass(), name, paramTypes);
            }
            throw e;
        }
    }

    private void invokePrivateVoidMethod(String methodName, Class<?>[] paramTypes, Object[] args) throws Exception {
        Method m = findMethod(EmailOTPAuthenticator.class, methodName, paramTypes);
        m.invoke(emailOTPAuthenticator, args);
    }

    private boolean invokePrivateBooleanMethod(String methodName, Class<?>[] paramTypes, Object[] args)
            throws Exception {
        Method m = findMethod(EmailOTPAuthenticator.class, methodName, paramTypes);
        return (Boolean) m.invoke(emailOTPAuthenticator, args);
    }

    private int invokePrivateIntMethod(String methodName, Class<?>[] paramTypes, Object[] args) throws Exception {
        Method m = findMethod(EmailOTPAuthenticator.class, methodName, paramTypes);
        return ((Number) m.invoke(emailOTPAuthenticator, args)).intValue();
    }

    /**
     * Test subclass that allows injecting runtime params so tests do not depend on context storage.
     */
    private static class TestEmailOTPAuthenticator extends EmailOTPAuthenticator {
        private Map<String, String> runtimeParams = new HashMap<>();

        void setRuntimeParams(Map<String, String> params) {
            this.runtimeParams = params != null ? params : new HashMap<>();
        }

        @Override
        public Map<String, String> getRuntimeParams(AuthenticationContext context) {
            return runtimeParams;
        }
    }
}
