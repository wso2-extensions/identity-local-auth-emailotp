/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.emailotp;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.captcha.connector.recaptcha.EmailOTPCaptchaConnector;
import org.wso2.carbon.identity.captcha.exception.CaptchaException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.exception.EmailOtpAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.emailotp.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.emailotp.util.AuthenticatorUtils;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OPERATION_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.identity.event.handler.notification.NotificationConstants.ARBITRARY_SEND_TO;
import static org.wso2.carbon.identity.event.handler.notification.NotificationConstants.EmailNotification.EMAIL_TEMPLATE_TYPE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.CODE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.DISPLAY_CODE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.LogConstants.ActionIDs.INITIATE_EMAIL_OTP_REQUEST;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.LogConstants.EMAIL_OTP_SERVICE;
import static org.wso2.carbon.user.core.UserCoreConstants.ErrorCode.USER_IS_LOCKED;
import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;

/**
 * This class contains the implementation of email OTP authenticator.
 */
@SuppressFBWarnings("SERVLET_PARAMETER")
public class EmailOTPAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static final long serialVersionUID = 2752231096259744926L;
    private static final Log log = LogFactory.getLog(EmailOTPAuthenticator.class);
    private static final String EMAIL_OTP_SENT = "EmailOTPSent";
    private static final String MASKED_EMAIL = "maskedEmail";
    private static final String AUTHENTICATOR_MESSAGE = "authenticatorMessage";
    private static final String IS_USER_NAME_RESOLVED = "isUserNameResolved";

    @Override
    public String getFriendlyName() {

        return AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getI18nKey() {

        return AuthenticatorConstants.AUTHENTICATOR_EMAIL_OTP;
    }

    @Override
    public String getName() {

        return AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_NAME;
    }

    @SuppressFBWarnings("SERVLET_SESSION_ID")
    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getRequestedSessionId();
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isDebugEnabled()) {
            log.debug("Inside EmailOTPAuthenticator canHandle method");
        }
        boolean canHandle = ((StringUtils.isNotBlank(request.getParameter(AuthenticatorConstants.RESEND))
                && StringUtils.isBlank(request.getParameter(CODE)))
                || StringUtils.isNotBlank(request.getParameter(CODE))
                || StringUtils.isNotBlank(request.getParameter(AuthenticatorConstants.USER_NAME)));
        if (canHandle && LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    EMAIL_OTP_SERVICE, FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.resultMessage("Email OTP Authenticator handling the authentication.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        AuthenticatorConstants.AuthenticationScenarios scenario = resolveScenario(request, context);
        switch (scenario) {
            case LOGOUT:
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            case INITIAL_OTP:
                initiateAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            default:
                // Resend OTP and OTP processing will be handled from here.
                return super.process(request, response, context);
        }
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        User user;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    EMAIL_OTP_SERVICE, INITIATE_EMAIL_OTP_REQUEST);
            diagnosticLogBuilder.resultMessage("Initiating email otp authentication request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        if (authenticatedUserFromContext == null) {
            if (context.isRetrying() && Boolean.parseBoolean(request.getParameter(AuthenticatorConstants.RESEND))) {
                redirectToEmailOTPLoginPage(null, null, context.getTenantDomain(),
                        response, request, context);
                return;
            }
            if (StringUtils.isEmpty(request.getParameter(AuthenticatorConstants.USER_NAME))) {
                redirectUserToIDF(response, context, request);
                context.setProperty(AuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR, true);
                return;
            }

            // When username is obtained through IDF page and the user is not yet set in the context.
            AuthenticatedUser authenticatedUser = resolveUser(request, context);
            user = getUser(authenticatedUser);
            if ((resolveUsernameFromRequest(request) != null) && (user == null)) {
                context.setProperty(IS_USER_NAME_RESOLVED, false);
            }
            if (user != null) {
                UserCoreUtil.setDomainInThreadLocal(user.getUserStoreDomain());
                authenticatedUser =
                        AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                                user.getFullQualifiedUsername());
                context.setSubject(authenticatedUser);
                authenticatedUserFromContext = authenticatedUser;
            }
        } else {
            if (isPreviousIdPAuthenticationFlowHandler(context)) {
                boolean isUserResolved = FrameworkUtils.getIsUserResolved(context);
                if (!isUserResolved) {
                    // If the user is not resolved, we need to resolve the user.
                    authenticatedUserFromContext = resolveUserFromUserStore(authenticatedUserFromContext)
                            .orElse(null);
                }
            }
        }
        if (authenticatedUserFromContext == null) {
            if (log.isDebugEnabled()) {
                log.debug("A user with the provided username was not found in the user stores.");
            }
            redirectToEmailOTPLoginPage(null, null, context.getTenantDomain(),
                    response, request, context);
            return;
        }
        String applicationTenantDomain = context.getTenantDomain();

        /*
        * We need to identify the username that the server is using to identify the user. This is needed to handle
        * federated scenarios, since for federated users, the username in the authentication context is not same as the
        * username when the user is provisioned to the server.
        */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);
        /*
        * If the mappedLocalUsername is blank, that means this is an initial login attempt by an non provisioned
        * federated user.
        */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);
        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, applicationTenantDomain, isInitialFederationAttempt, context);
        String email = resolveEmailOfAuthenticatedUser(authenticatingUser, applicationTenantDomain,
                context, isInitialFederationAttempt);
        if (StringUtils.isBlank(email)) {
            redirectToEmailOTPLoginPage(null, null, context.getTenantDomain(),
                    response, request, context);
            return;
        }
        if (!isInitialFederationAttempt && AuthenticatorUtils.isAccountLocked(authenticatingUser)) {
            handleOTPForLockedUser(authenticatingUser, request, response, context);
            return;
        }
        AuthenticatorConstants.AuthenticationScenarios scenario = resolveScenario(request, context);
        if (scenario == AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP ||
                scenario == AuthenticatorConstants.AuthenticationScenarios.RESEND_OTP) {
            /*
             * Here we need to pass the authenticated user as the authenticated user from context since the events needs
             * to triggered against the context user.
             */
            sendEmailOtp(email, applicationTenantDomain, authenticatedUserFromContext, scenario, context);
            publishPostEmailOTPGeneratedEvent(authenticatedUserFromContext, request, context);
            redirectToEmailOTPLoginPage(authenticatedUserFromContext.getUserName(), email, applicationTenantDomain,
                    response, request, context);
            return;
        }
        redirectToEmailOTPLoginPage(authenticatedUserFromContext.getUserName(), email, applicationTenantDomain,
                response, request, context);
    }

    private Optional<AuthenticatedUser> resolveUserFromUserStore(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException {

        return Optional.ofNullable(getUser(authenticatedUser))
                .map(AuthenticatedUser::new);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    EMAIL_OTP_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.resultMessage("Processing email otp authentication response.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParams(getApplicationDetails(context));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        context.removeProperty(AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP);

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        if (authenticatedUserFromContext == null) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_USER_FOUND, context);
        } else if (isPreviousIdPAuthenticationFlowHandler(context)) {
            User user = getUser(authenticatedUserFromContext);
            if (user != null) {
                authenticatedUserFromContext = new AuthenticatedUser(user);
            }
        }

        String applicationTenantDomain = context.getTenantDomain();

        /*
        * We need to identify the username that the server is using to identify the user. This is needed to handle
        * federated scenarios, since for federated users, the username in the authentication context is not same as the
        * username when the user is provisioned to the server.
        */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);
        /*
        * If the mappedLocalUsername is blank, that means this is an initial login attempt by an non provisioned
        * federated user.
        */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);
        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, applicationTenantDomain, isInitialFederationAttempt, context);
        if (!isInitialFederationAttempt && AuthenticatorUtils.isAccountLocked(authenticatingUser)) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_USER_ACCOUNT_LOCKED, context,
                    authenticatingUser.getUserName());
        }
        if (StringUtils.isBlank(request.getParameter(CODE))) {
            throw handleInvalidCredentialsScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_OTP_CODE,
                    authenticatedUserFromContext.getUserName());
        }
        if (Boolean.parseBoolean(request.getParameter(AuthenticatorConstants.RESEND))) {
            throw handleInvalidCredentialsScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_RETRYING_OTP_RESEND,
                    authenticatedUserFromContext.getUserName());
        }
        boolean isSuccessfulAttempt =
                isSuccessfulAuthAttempt(request.getParameter(CODE), applicationTenantDomain,
                        authenticatingUser, context);
        if (isSuccessfulAttempt) {
            // It reached here means the authentication was successful.
            if (log.isDebugEnabled()) {
                log.debug(String.format("User: %s authenticated successfully via email OTP",
                        authenticatedUserFromContext.getUserName()));
            }
            if (!isInitialFederationAttempt) {
                // A mapped user is not available for isInitialFederationAttempt true scenario.
                resetOtpFailedAttempts(authenticatingUser, context);
            }
            publishPostEmailOTPValidatedEvent(authenticatedUserFromContext, true,
                    false, request, context);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        EMAIL_OTP_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
                diagnosticLogBuilder.resultMessage("Email OTP authentication successful.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParams(getApplicationDetails(context))
                        .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                LoggerUtils.getMaskedContent(authenticatedUserFromContext.getUserName()) :
                                authenticatedUserFromContext.getUserName());
                Optional<String> optionalUserId = getUserId(authenticatedUserFromContext);
                optionalUserId.ifPresent(userId -> diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID,
                        userId));
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return;
        }
        /*
        * Handle when the email OTP is unsuccessful. At this point user account is not locked. Locked scenario is
        * handled from the above steps.
        */
        if (!isInitialFederationAttempt) {
            // A mapped user is not available for isInitialFederationAttempt true scenario.
            handleOtpVerificationFail(authenticatingUser , context);
        }
        if (Boolean.parseBoolean(context.getProperty(AuthenticatorConstants.OTP_EXPIRED).toString())) {
            publishPostEmailOTPValidatedEvent(authenticatedUserFromContext, false,
                    true, request, context);
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_OTP_EXPIRED, context,
                    authenticatedUserFromContext.getUserName());
        } else {
            publishPostEmailOTPValidatedEvent(authenticatedUserFromContext, false,
                    false, request, context);
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_OTP_INVALID, context,
                    authenticatedUserFromContext.getUserName());
        }
    }

    @Override
    public boolean isSatisfyAuthenticatorPrerequisites(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        // Check whether user has a email address attribute configured to authenticate with the Email OTP authenticator.
        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
        if (authenticatedUserFromContext == null
                || isPreviousIdPAuthenticationFlowHandler(context)
                || Boolean.parseBoolean(String.valueOf(context.getParameter(
                AuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR)))) {
            return true;
        }
        String applicationTenantDomain = context.getTenantDomain();
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);

        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);
        AuthenticatedUser authenticatingUser = resolveAuthenticatingUser(authenticatedUserFromContext,
                mappedLocalUsername, applicationTenantDomain, isInitialFederationAttempt, context);
        if (authenticatingUser != null) {
            String email = resolveEmailOfAuthenticatedUser(authenticatingUser, applicationTenantDomain,
                    context, isInitialFederationAttempt);
            if (StringUtils.isEmpty(email)) {
                // Add the reason that user cannot authenticate with, to the endpoint param of the context.
                context.addEndpointParam(FrameworkConstants.NOT_SATISFY_PREREQUISITES_REASON + "." +
                                AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_NAME,
                        AuthenticatorConstants.EMAIL_OTP_EMAIL_NOT_FOUND_ERROR_CODE);
                return false;
            }
            return true;
        }
        throw new AuthenticationFailedException(
                AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER.getCode(),
                AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_AUTHENTICATED_USER.getMessage());
    }

    /**
     * Identify the AuthenticatedUser that the authenticator trying to authenticate. This needs to be done to
     * identify the locally mapped user for federated authentication scenarios.
     *
     * @param authenticatedUserInContext AuthenticatedUser retrieved from context.
     * @param mappedLocalUsername        Mapped local username if available.
     * @param tenantDomain               Application tenant domain.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return AuthenticatedUser that the authenticator trying to authenticate.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private AuthenticatedUser resolveAuthenticatingUser(AuthenticatedUser authenticatedUserInContext,
                                                        String mappedLocalUsername,
                                                        String tenantDomain, boolean isInitialFederationAttempt,
                                                        AuthenticationContext context)
            throws AuthenticationFailedException {

        // This is a federated initial authentication scenario.
        if (isInitialFederationAttempt) {
            return authenticatedUserInContext;
        }
        // Handle local users.
        if (!authenticatedUserInContext.isFederatedUser()) {
            return authenticatedUserInContext;
        }
        /*
        * At this point, the authenticating user is in our system but has a different mapped username compared to the
        * identifier that is in the authentication context. Therefore, we need to have a new AuthenticatedUser object
        * with the mapped local username to identify the user.
        */
        AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
        authenticatingUser.setUserName(mappedLocalUsername);
        authenticatingUser.setUserStoreDomain(getFederatedUserstoreDomain(authenticatedUserInContext, tenantDomain,
                context));
        return authenticatingUser;
    }

    private AuthenticatorConstants.AuthenticationScenarios resolveScenario(HttpServletRequest request,
                                                                           AuthenticationContext context) {

        if (context.isLogoutRequest()) {
            return AuthenticatorConstants.AuthenticationScenarios.LOGOUT;
        } else if (!context.isRetrying() && StringUtils.isBlank(request.getParameter(CODE)) &&
                StringUtils.isBlank(request.getParameter(AuthenticatorConstants.RESEND))) {
            return AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP;
        } else if (context.isRetrying() &&
                StringUtils.isNotBlank(request.getParameter(AuthenticatorConstants.RESEND)) &&
                Boolean.parseBoolean(request.getParameter(AuthenticatorConstants.RESEND))) {
            return AuthenticatorConstants.AuthenticationScenarios.RESEND_OTP;
        }
        return AuthenticatorConstants.AuthenticationScenarios.SUBMIT_OTP;
    }

    /**
     * Reset OTP Failed Attempts count upon successful completion of the OTP verification. By default the email OTP
     * authenticator will support account lock on failed attempts if the account locking is enabled for the tenant.
     *
     * @param user AuthenticatedUser.
     * @throws AuthenticationFailedException If an error occurred while resetting the OTP failed attempts.
     */
    private void resetOtpFailedAttempts(AuthenticatedUser user , AuthenticationContext context)
            throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(user, context);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_NAME);
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM,
                AuthenticatorConstants.Claims.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM);
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, true);

        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties, context);
    }

    /**
     * Execute account lock flow for OTP verification failures. By default the email OTP
     * authenticator will support account lock on failed attempts if the account locking is enabled for the tenant.
     *
     * @param user AuthenticatedUser.
     * @throws AuthenticationFailedException If an error occurred while resetting the OTP failed attempts.
     */
    private void handleOtpVerificationFail(AuthenticatedUser user , AuthenticationContext context)
            throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(user, context);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_NAME);
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM,
                AuthenticatorConstants.Claims.EMAIL_OTP_FAILED_ATTEMPTS_CLAIM);
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, false);

        triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties, context);
    }

    /**
     * Check whether the given OTP value is valid.
     *
     * @param userToken    User given otp.
     * @param tenantDomain Tenant domain.
     * @param user         AuthenticatedUser.
     * @param context      AuthenticationContext.
     * @return True if the OTP is valid.
     * @throws AuthenticationFailedException If error occurred while validating the OTP.
     */
    private boolean isSuccessfulAuthAttempt(String userToken, String tenantDomain, AuthenticatedUser user,
                                            AuthenticationContext context) throws AuthenticationFailedException {

        String tokenInContext = (String) context.getProperty(AuthenticatorConstants.OTP_TOKEN);
        if (StringUtils.isBlank(userToken)) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_OTP_CODE, context, user.getUserName());
        }
        if (StringUtils.isBlank(tokenInContext)) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_OTP_CODE_IN_CONTEXT,
                    context, user.getUserName());
        }
        boolean isExpired = isOtpExpired(tenantDomain, context);
        if (userToken.equals(tokenInContext)) {
            if (isExpired) {
                context.setProperty(AuthenticatorConstants.OTP_EXPIRED, Boolean.toString(true));
                return false;
            } else {
                context.setProperty(AuthenticatorConstants.OTP_EXPIRED, Boolean.toString(false));
                context.setProperty(AuthenticatorConstants.OTP_TOKEN, StringUtils.EMPTY);
                context.setProperty(AuthenticatorConstants.OTP_GENERATED_TIME, StringUtils.EMPTY);
                context.setSubject(user);
                return true;
            }
        } else if (isBackupCodeEnabled(tenantDomain, context)) {
            if (log.isDebugEnabled()) {
                log.debug("Checking OTP given by the user: " + user.getUserName() + " with backup codes");
            }
            return isValidBackupCode(userToken, user, context);
        }
        // This is the OTP mismatched scenario.
        if (log.isDebugEnabled()) {
            log.debug("Invalid OTP given by the user: " + user.getUserName());
        }
        return false;
    }

    /**
     * Check whether the entered code matches with a backup code.
     *
     * @param userToken The userToken.
     * @param user      The authenticatedUser.
     * @param context   The AuthenticationContext.
     * @return True if the user entered code matches with a backup code.
     * @throws AuthenticationFailedException If an error occurred validating backup with backup codes.
     */
    private boolean isValidBackupCode(String userToken, AuthenticatedUser user,
                                      AuthenticationContext context) throws AuthenticationFailedException {

        String fullyQualifiedUsername = user.toFullQualifiedUsername();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(fullyQualifiedUsername);
        // Get the saved backup codes from the user store for the user.
        String savedBackupCodes =
                getUserClaimValueFromUserStore(AuthenticatorConstants.Claims.OTP_BACKUP_CODES_CLAIM, user,
                        AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_BACKUP_CODES, context);
        if (StringUtils.isBlank(savedBackupCodes)) {
            if (log.isDebugEnabled()) {
                log.debug("No backup codes found for user: " + user.getUserName());
            }
            return false;
        }
        List<String> backupCodes = Arrays.asList(savedBackupCodes.split(AuthenticatorConstants.BACKUP_CODES_SEPARATOR));
        if (backupCodes.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("No backup codes found for user: " + user.getUserName());
            }
            return false;
        }

        // Check whether the user given token matches with the backup codes.
        if (!backupCodes.contains(userToken)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Given OTP: %s does not match with any saved backup codes codes for user: %s",
                        userToken, user.getUserName()));
            }
            context.setProperty(AuthenticatorConstants.CODE_MISMATCH, true);
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Saved backup code found for the user: " + user.getUserName());
        }
        context.setSubject(user);
        removeUsedBackupCode(userToken, tenantAwareUsername, new ArrayList<>(backupCodes), user , context);
        return true;
    }

    /**
     * Remove the used otp from the saved OTP list for the user.
     *
     * @param userToken           OTP given by the user.
     * @param tenantAwareUsername Tenant aware username.
     * @param backupCodes         Existing OTP backup codes list.
     * @param user                AuthenticatedUser.
     * @throws AuthenticationFailedException If an error occurred while removing the used otp.
     */
    private void removeUsedBackupCode(String userToken, String tenantAwareUsername, List<String> backupCodes,
                                      AuthenticatedUser user , AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        backupCodes.remove(userToken);
        String unusedBackupCodes = String.join(AuthenticatorConstants.BACKUP_CODES_SEPARATOR, backupCodes);
        try {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Removing used token: %s from the backup OTP list of user: %s", userToken,
                        user.getUserName()));
            }
            UserStoreManager userStoreManager = getUserStoreManager(user, authenticationContext);
            Map<String, String> claimsToUpdate = new HashMap<>();
            claimsToUpdate.put(AuthenticatorConstants.Claims.OTP_BACKUP_CODES_CLAIM, unusedBackupCodes);
            userStoreManager.setUserClaimValues(tenantAwareUsername, claimsToUpdate, null);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_UPDATING_BACKUP_CODES,
                    e, authenticationContext, user.getUserName());
        }
    }

    /**
     * Checks whether otp is Expired or not.
     *
     * @param tenantDomain Tenant domain.
     * @param context      Authentication Context.
     */
    private boolean isOtpExpired(String tenantDomain, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (context.getProperty(AuthenticatorConstants.OTP_GENERATED_TIME) == null) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_GENERATED_TIME,
                    context);
        }
        long generatedTime = (long) context.getProperty(AuthenticatorConstants.OTP_GENERATED_TIME);
        long expireTime = getOtpValidityPeriod(tenantDomain, context);
        return System.currentTimeMillis() >= generatedTime + expireTime;
    }

    /**
     * Send the one time password to the authenticated user via an email. This function generates the OTP it self
     * and triggers email notification.
     *
     * @param email             Email address.
     * @param tenantDomain      Tenant domain.
     * @param authenticatedUser Authenticated user.
     * @param scenario          Scenario.
     * @param context           AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred while sending the OTP notification to the user.
     */
    private void sendEmailOtp(String email, String tenantDomain, AuthenticatedUser authenticatedUser,
                              AuthenticatorConstants.AuthenticationScenarios scenario, AuthenticationContext context)
            throws AuthenticationFailedException {

        String otp = generateOTP(tenantDomain, context);
        context.setProperty(AuthenticatorConstants.OTP_TOKEN, otp);
        context.setProperty(AuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        context.setProperty(AuthenticatorConstants.OTP_EXPIRED, Boolean.toString(false));

        Map<String, Object> metaProperties = new HashMap<>();
        // Pass the service provider name to event framework.
        if (StringUtils.isNotBlank(context.getServiceProviderName())) {
            metaProperties.put(AuthenticatorConstants.SERVICE_PROVIDER_NAME, context.getServiceProviderName());
        }
        metaProperties.put(CODE, otp);
        metaProperties.put(EMAIL_TEMPLATE_TYPE, AuthenticatorConstants.EMAIL_OTP_TEMPLATE_NAME);
        metaProperties.put(ARBITRARY_SEND_TO, email);
        String maskedEmailAddress = getMaskedEmailAddress(authenticatedUser.getUserName(), email, tenantDomain,
                context);
        setAuthenticatorMessage(context, maskedEmailAddress);

        /* SaaS apps are created at the super tenant level and they can be accessed by users of other organizations.
        If users of other organizations try to login to a saas app, the email notification should be triggered from the
        email provider configured for that organization. Hence, we need to start a new tenanted flow here. */
        if (context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
            try {
                FrameworkUtils.startTenantFlow(authenticatedUser.getTenantDomain());
                triggerEvent(IdentityEventConstants.Event.TRIGGER_NOTIFICATION, authenticatedUser, metaProperties,
                        context);
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        } else {
            triggerEvent(IdentityEventConstants.Event.TRIGGER_NOTIFICATION, authenticatedUser, metaProperties, context);
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    EMAIL_OTP_SERVICE, AuthenticatorConstants.LogConstants.ActionIDs.SEND_EMAIL_OTP);
            diagnosticLogBuilder.resultMessage("Email OTP sent successfully.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .inputParam("user store domain", authenticatedUser.getUserStoreDomain())
                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(authenticatedUser.getUserName()) :
                            authenticatedUser.getUserName())
                    .inputParam("scenario", scenario.name())
                    .inputParams(getApplicationDetails(context));
            Optional<String> optionalUserId = getUserId(authenticatedUser);
            optionalUserId.ifPresent(userId -> diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID, userId));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
    }

    private static void setAuthenticatorMessage(AuthenticationContext context, String maskedEmailAddress) {

        String message = "The code is successfully sent to the email ID: " + maskedEmailAddress;
        Map<String, String> messageContext = new HashMap<>();
        messageContext.put(MASKED_EMAIL, maskedEmailAddress);

        AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(FrameworkConstants.
                AuthenticatorMessageType.INFO, EMAIL_OTP_SENT, message, messageContext);

        context.setProperty(AUTHENTICATOR_MESSAGE, authenticatorMessage);
    }

    /**
     * To redirect the flow to email otp login page to enter an OTP.
     *
     * @param username     Username.
     * @param email        Email address of the authenticated user.
     * @param tenantDomain Tenant domain.
     * @param response     HttpServletResponse.
     * @param request      HttpServletRequest.
     * @param context      AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred while redirecting to email otp login page.
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    private void redirectToEmailOTPLoginPage(String username, String email, String tenantDomain,
                                             HttpServletResponse response, HttpServletRequest request,
                                             AuthenticationContext context)
            throws AuthenticationFailedException {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryParam(request);
        try {
            String emailOTPLoginPage = AuthenticatorUtils.getEmailOTPLoginPageUrl(context);
            String url = getRedirectURL(emailOTPLoginPage, queryParams, multiOptionURI);
            // Set the email address in the UI by masking it.
            if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(email)
                    && !Boolean.parseBoolean(
                    String.valueOf(context.getParameter(
                            AuthenticatorConstants.IS_IDF_INITIATED_FROM_AUTHENTICATOR)))) {
                url = url + AuthenticatorConstants.SCREEN_VALUE_QUERY_PARAM +
                        getMaskedEmailAddress(username, email, tenantDomain, context);
            }
            if (context.isRetrying() && !Boolean.parseBoolean(request.getParameter(AuthenticatorConstants.RESEND))) {
                url = url + AuthenticatorConstants.RETRY_QUERY_PARAMS;
            }
            if (Boolean.parseBoolean(request.getParameter(AuthenticatorConstants.RESEND))) {
                url = url + AuthenticatorConstants.RESEND_CODE_PARAM;
            }
            url = url + getCaptchaParams(request, context);
            response.sendRedirect(url);
            context.setProperty(AuthenticatorConstants.IS_REDIRECT_TO_EMAIL_OTP, "true");
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                publishInitiateAuthRedirectionDiagnosticLogs("Redirecting to email otp login page.", context);
            }
        } catch (IOException e) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE, e, context,
                    (Object) null);
        }
    }

    /**
     * Get the masked email address.
     *
     * @param username     Username.
     * @param email        Email address to be masked.
     * @param tenantDomain Tenant domain.
     * @return Masked email address.
     * @throws AuthenticationFailedException If an error occurred while masking the given email.
     */
    private String getMaskedEmailAddress(String username, String email, String tenantDomain,
                                         AuthenticationContext context)
            throws AuthenticationFailedException {

        String emailAddressRegex = getEmailMaskingPattern(tenantDomain, context);
        if (StringUtils.isBlank(emailAddressRegex)) {
            log.debug(String.format("Email address masking regex is not set in tenant: %s. Therefore showing the " +
                    "complete email address for user: %s", tenantDomain, username));
            return email;
        }
        return email.replaceAll(emailAddressRegex, AuthenticatorConstants.EMAIL_ADDRESS_MASKING_CHARACTER);
    }

    /**
     * Trigger event after validating Email OTP.
     *
     * @param request                HttpServletRequest.
     * @param isAuthenticationPassed Whether the authentication passed.
     * @param isExpired              Whether the code is expired.
     * @param context                Authentication context.
     * @param authenticatedUser      Authenticated user.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    private void publishPostEmailOTPValidatedEvent(AuthenticatedUser authenticatedUser, boolean isAuthenticationPassed,
                                                   boolean isExpired, HttpServletRequest request,
                                                   AuthenticationContext context)
            throws AuthenticationFailedException {

        String tenantDomain = context.getTenantDomain();

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCallerSessionKey());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, context.getServiceProviderName());
        eventProperties.put(IdentityEventConstants.EventProperty.USER_INPUT_OTP, request.getParameter(
                CODE));
        eventProperties.put(IdentityEventConstants.EventProperty.OTP_USED_TIME, System.currentTimeMillis());

        // Add otp status to the event properties.
        if (isAuthenticationPassed) {
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS, AuthenticatorConstants.STATUS_SUCCESS);
            eventProperties.put(IdentityEventConstants.EventProperty.GENERATED_OTP, request.getParameter(
                    CODE));
        } else {
            if (isExpired) {
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS,
                        AuthenticatorConstants.STATUS_OTP_EXPIRED);
                // Add generated time and expiry time info for the event.
                long otpGeneratedTime = (long) context.getProperty(AuthenticatorConstants.OTP_GENERATED_TIME);
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME, otpGeneratedTime);
                long expiryTime = otpGeneratedTime + getOtpValidityPeriod(tenantDomain, context);
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, expiryTime);
            } else {
                eventProperties.put(IdentityEventConstants.EventProperty.OTP_STATUS,
                        AuthenticatorConstants.STATUS_CODE_MISMATCH);
            }
        }
        triggerEvent(IdentityEventConstants.Event.POST_VALIDATE_EMAIL_OTP, authenticatedUser, eventProperties ,
                context);
    }

    /**
     * Trigger event after generating Email OTP.
     *
     * @param authenticatedUser Authenticated user.
     * @param request           HttpServletRequest.
     * @param context           Authentication context.
     * @throws AuthenticationFailedException If ann error occurred while triggering the event.
     */
    private void publishPostEmailOTPGeneratedEvent(AuthenticatedUser authenticatedUser, HttpServletRequest request,
                                                   AuthenticationContext context)
            throws AuthenticationFailedException {

        String tenantDomain = context.getTenantDomain();
        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCallerSessionKey());
        eventProperties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, context.getServiceProviderName());
        if (StringUtils.isNotBlank(request.getParameter(AuthenticatorConstants.RESEND))) {
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE, request.getParameter(
                    AuthenticatorConstants.RESEND));
        } else {
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE, false);
        }
        // Add OTP generated time and OTP expiry time to the event.
        Object otpGeneratedTimeProperty = context.getProperty(AuthenticatorConstants.OTP_GENERATED_TIME);
        if (otpGeneratedTimeProperty != null) {
            long otpGeneratedTime = (long) otpGeneratedTimeProperty;
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME, otpGeneratedTime);

            // Calculate OTP expiry time.
            long expiryTime = otpGeneratedTime + getOtpValidityPeriod(tenantDomain, context);
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, expiryTime);
        }
        triggerEvent(IdentityEventConstants.Event.POST_GENERATE_EMAIL_OTP, authenticatedUser, eventProperties, context);
    }

    /**
     * Trigger event.
     *
     * @param eventName      Event name.
     * @param user           Authenticated user.
     * @param metaProperties Meta details.
     * @throws AuthenticationFailedException If an error occurred while triggering the event.
     */
    private void triggerEvent(String eventName, AuthenticatedUser user,
                              Map<String, Object> metaProperties , AuthenticationContext context)
            throws AuthenticationFailedException {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        if (metaProperties != null) {
            for (Map.Entry<String, Object> metaProperty : metaProperties.entrySet()) {
                if (StringUtils.isNotBlank(metaProperty.getKey()) && metaProperty.getValue() != null) {
                    properties.put(metaProperty.getKey(), metaProperty.getValue());
                }
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            String receiver = (String) properties.get("send-to");
            if (LoggerUtils.isDiagnosticLogsEnabled() && eventName.equals(IdentityEventConstants.Event
                    .TRIGGER_NOTIFICATION)) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        AuthenticatorConstants.LogConstants.EMAIL_OTP_SERVICE,
                        AuthenticatorConstants.LogConstants.ActionIDs.SEND_EMAIL_OTP);
                diagnosticLogBuilder
                        .inputParam(LogConstants.InputKeys.TENANT_DOMAIN, user.getTenantDomain())
                        .inputParam(LogConstants.InputKeys.USER_ID, user.getLoggableMaskedUserId())
                        .inputParam(LogConstants.InputKeys.SERVICE_PROVIDER, properties.get("serviceProviderName"))
                        .inputParam(AuthenticatorConstants.LogConstants.InputKeys.EMAIL_TO,
                                LoggerUtils.isLogMaskingEnable ?
                                        LoggerUtils.getMaskedContent(receiver) : receiver)
                        .resultMessage("Email sending event will be triggered.")
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            AuthenticatorDataHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_TRIGGERING_EVENT, e,
                    context, eventName, user.getUserName());
        }
    }

    /**
     * Handle email OTP account locked users.
     *
     * @param authenticatedUser Authenticated user provisioned in the server.
     * @param response          HttpServletResponse.
     * @param context           AuthenticationContext.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private void handleOTPForLockedUser(AuthenticatedUser authenticatedUser, HttpServletRequest request,
            HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                context.getCallerSessionKey(), context.getContextIdentifier());
        String retryParam;
        // By default we are showing the authentication failure reason here.
        long unlockTime = getUnlockTimeInMilliSeconds(authenticatedUser, context);
        long timeToUnlock = unlockTime - System.currentTimeMillis();
        if (timeToUnlock > 0) {
            queryParams += AuthenticatorConstants.UNLOCK_QUERY_PARAM + Math.round((double) timeToUnlock / 1000 / 60);
        }
        // Locked reason.
        String lockedReason = getLockedReason(authenticatedUser, context);
        if (StringUtils.isNotBlank(lockedReason)) {
            queryParams += AuthenticatorConstants.LOCKED_REASON_QUERY_PARAM + lockedReason;
        }
        queryParams += AuthenticatorConstants.ERROR_CODE_QUERY_PARAM + USER_IS_LOCKED;
        retryParam = AuthenticatorConstants.ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS;
        redirectToErrorPage(request, response, context, queryParams, retryParam);
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            publishInitiateAuthRedirectionDiagnosticLogs("Redirecting to error page.", context);
        }
    }

    /**
     * To redirect flow to error page with specific condition.
     *
     * @param response    The httpServletResponse.
     * @param context     The AuthenticationContext.
     * @param queryParams The query params.
     * @param retryParam  The retry param.
     * @throws AuthenticationFailedException If an error occurred.
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    private void redirectToErrorPage(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context, String queryParams, String retryParam)
            throws AuthenticationFailedException {

        try {
            String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryParam(request);
            String errorPage = AuthenticatorUtils.getEmailOTPErrorPageUrl(context);
            String url = getRedirectURL(errorPage, queryParams, multiOptionURI);
            response.sendRedirect(url + retryParam);
        } catch (IOException e) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE, context
                    , e, (Object) null);
        }
    }

    /**
     * To get the redirection URL.
     *
     * @param baseURI     the base path
     * @param queryParams the queryParams
     * @param multiOptionURI the multiOptionURI
     * @return url
     */
    private String getRedirectURL(String baseURI, String queryParams, String multiOptionURI) {

        StringBuilder queryStringBuilder = new StringBuilder();
        if (StringUtils.isNotEmpty(queryParams)) {
            queryStringBuilder.append(queryParams).append("&");
        }
        queryStringBuilder.append(AuthenticatorConstants.AUTHENTICATORS_QUERY_PARAM).append(getName());
        if (StringUtils.isNotEmpty(multiOptionURI)) {
            queryStringBuilder.append(multiOptionURI);
        }
        return FrameworkUtils.appendQueryParamsStringToUrl(baseURI, queryStringBuilder.toString());
    }

    /**
     * Get user account unlock time in milli seconds. If no value configured for unlock time user claim, return 0.
     *
     * @param authenticatedUser The authenticated user.
     * @return User account unlock time in milli seconds. If no value is configured return 0.
     * @throws AuthenticationFailedException If an error occurred while getting the user unlock time.
     */
    private long getUnlockTimeInMilliSeconds(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = authenticatedUser.toFullQualifiedUsername();
        String accountLockedTime =
                getUserClaimValueFromUserStore(AuthenticatorConstants.Claims.ACCOUNT_UNLOCK_TIME_CLAIM,
                        authenticatedUser,
                        AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME, context);
        if (StringUtils.isBlank(accountLockedTime)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No value configured for claim: %s for user: %s",
                        AuthenticatorConstants.Claims.ACCOUNT_UNLOCK_TIME_CLAIM, username));
            }
            return 0;
        }
        return Long.parseLong(accountLockedTime);
    }

    private String getLockedReason(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = authenticatedUser.toFullQualifiedUsername();
        String lockedReason = getUserClaimValueFromUserStore(
                AuthenticatorConstants.Claims.ACCOUNT_LOCKED_REASON_CLAIM, authenticatedUser,
                AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME, context);
        if (StringUtils.isBlank(lockedReason) && (log.isDebugEnabled())) {
            log.debug(String.format("No value configured for claim: %s for user: %s",
                    AuthenticatorConstants.Claims.ACCOUNT_LOCKED_REASON_CLAIM, username));
        }
        return lockedReason;
    }

    /**
     * Resolve the email address of the authenticated user.
     *
     * @param user                       Authenticated user.
     * @param tenantDomain               Application tenant domain.
     * @param context                    AuthenticationContext.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return Email of the authenticated user.
     * @throws AuthenticationFailedException If an error occurred while resolving the email address.
     */
    private String resolveEmailOfAuthenticatedUser(AuthenticatedUser user, String tenantDomain,
                                                   AuthenticationContext context, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        String email;
        if (isInitialFederationAttempt) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Getting the email of the initially federating user: %s", user.getUserName()));
            }
            email = getEmailForFederatedUser(user, tenantDomain, context);
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Getting the email of the local user: %s in userstore: %s in " +
                        "tenant: %s", user.getUserName(), user.getUserStoreDomain(), user.getTenantDomain()));
            }
            email = getUserClaimValueFromUserStore(AuthenticatorConstants.Claims.EMAIL_CLAIM, user,
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_EMAIL_ADDRESS, context);
        }
        return email;
    }

    /**
     * Retrieve the email address of the federated user.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Application tenant domain.
     * @param context      AuthenticationContext.
     * @return Email address of the federated user.
     * @throws AuthenticationFailedException If an error occurred while getting the email address of the federated user.
     */
    private String getEmailForFederatedUser(AuthenticatedUser user, String tenantDomain,
                                            AuthenticationContext context) throws AuthenticationFailedException {

        String emailAttributeKey = resolveEmailAddressAttribute(user, tenantDomain, context);
        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
        String email = null;
        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
            String key = String.valueOf(entry.getKey().getLocalClaim().getClaimUri());
            String value = entry.getValue();
            if (key.equals(emailAttributeKey)) {
                email = String.valueOf(value);
                break;
            }
        }
        return email;
    }

    /**
     * Resolve the email address attribute for the federated user by evaluating the federated IDP.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Application tenant domain.
     * @param context      AuthenticationContext.
     * @return Email address attribute.
     * @throws AuthenticationFailedException If an error occurred while resolving email address attribute.
     */
    private String resolveEmailAddressAttribute(AuthenticatedUser user, String tenantDomain,
                                                AuthenticationContext context) throws AuthenticationFailedException {

        String dialect = getFederatedAuthenticatorDialect(context);
        if (AuthenticatorConstants.OIDC_DIALECT_URI.equals(dialect)) {
            return AuthenticatorConstants.EMAIL_ATTRIBUTE_KEY;
        }
        // If the dialect is not OIDC we need to check claim mappings for the email claim mapped attribute.
        String idpName = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(idpName, tenantDomain, context);
        ClaimConfig claimConfigs = idp.getClaimConfig();
        if (claimConfigs == null) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_CLAIM_CONFIGS_IN_FEDERATED_AUTHENTICATOR,
                    context, idpName, tenantDomain);
        }
        ClaimMapping[] claimMappings = claimConfigs.getClaimMappings();
        if (ArrayUtils.isEmpty(claimMappings)) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_CLAIM_CONFIGS_IN_FEDERATED_AUTHENTICATOR,
                    context, idpName, tenantDomain);
        }

        String emailAttributeKey = null;
        for (ClaimMapping claimMapping : claimMappings) {
            if (AuthenticatorConstants.Claims.EMAIL_CLAIM.equals(claimMapping.getLocalClaim().getClaimUri())) {
                emailAttributeKey = claimMapping.getRemoteClaim().getClaimUri();
                break;
            }
        }
        if (StringUtils.isBlank(emailAttributeKey)) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_EMAIL_CLAIM_MAPPINGS,
                    context, idpName, tenantDomain);
        }
        return emailAttributeKey;
    }

    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain,
                                                 AuthenticationContext context) throws
            AuthenticationFailedException {

        try {
            IdentityProvider idp = AuthenticatorDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw handleAuthErrorScenario(
                        AuthenticatorConstants.ErrorMessages.ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR, context,
                        idpName, tenantDomain);
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR, context,
                    idpName, tenantDomain);
        }
    }

    /**
     * Retrieve the claim dialect of the federated authenticator.
     *
     * @param context AuthenticationContext.
     * @return The claim dialect of the federated authenticator.
     */
    private String getFederatedAuthenticatorDialect(AuthenticationContext context) {

        String dialect = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        for (StepConfig stepConfig : stepConfigMap.values()) {
            if (stepConfig.isSubjectAttributeStep()) {
                dialect = stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator().getClaimDialectURI();
                break;
            }
        }
        return dialect;
    }

    /**
     * Get the authenticated user by iterating though auth steps.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser.
     * @throws AuthenticationFailedException If no authenticated user was found.
     */
    private AuthenticatedUser getAuthenticatedUserFromContext(AuthenticationContext context)
            throws AuthenticationFailedException {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        StepConfig currentStepConfig = stepConfigMap.get(context.getCurrentStep());
        for (StepConfig stepConfig : stepConfigMap.values()) {
            AuthenticatedUser user = stepConfig.getAuthenticatedUser();
            if (stepConfig.isSubjectAttributeStep() && user != null) {
                if (StringUtils.isBlank(user.toFullQualifiedUsername())) {
                    if (log.isDebugEnabled()) {
                        log.debug("Username can not be empty");
                    }
                    throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_USERNAME,
                            context);
                }
                return user;
            }
        }

        if (context.getLastAuthenticatedUser() != null
                && context.getLastAuthenticatedUser().getUserName() != null) {
            return context.getLastAuthenticatedUser();
        }

        if (currentStepConfig.isSubjectAttributeStep()) {
            return null;
        }
        // If authenticated user cannot be found from the previous steps.
        throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_USER_FOUND, context);
    }

    /**
     * Get UserStoreManager for the given user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return UserStoreManager.
     * @throws AuthenticationFailedException If an error occurred while getting the UserStoreManager.
     */
    private UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        UserRealm userRealm = getTenantUserRealm(authenticatedUser.getTenantDomain(), context);
        String username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername());
        String userstoreDomain = authenticatedUser.getUserStoreDomain();
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                throw handleAuthErrorScenario(
                        AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER, context,
                        username);
            }
            if (StringUtils.isBlank(userstoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userstoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userstoreDomain);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER,
                    e, context, username);
        }
    }

    /**
     * Get the UserRealm for the user given user.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm.
     * @throws AuthenticationFailedException If an error occurred while getting the UserRealm.
     */
    private UserRealm getTenantUserRealm(String tenantDomain, AuthenticationContext context)
            throws AuthenticationFailedException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (AuthenticatorDataHolder.getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM,
                    e, context, tenantDomain);
        }
        if (userRealm == null) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_USER_REALM,
                    context, tenantDomain);
        }
        return userRealm;
    }

    /**
     * Get user claim value.
     *
     * @param claimUri          Claim uri.
     * @param authenticatedUser AuthenticatedUser.
     * @param error             Error associated with the claim retrieval.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    private String getUserClaimValueFromUserStore(String claimUri, AuthenticatedUser authenticatedUser,
                                                  AuthenticatorConstants.ErrorMessages error,
                                                  AuthenticationContext context)
            throws AuthenticationFailedException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser, context);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()), new String[]{claimUri}, null);
            return claimValues.get(claimUri);
        } catch (UserStoreException e) {
            throw handleAuthErrorScenario(error, e, context, authenticatedUser.getUserName());
        }
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    private String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }
        // If the user is federated, we need to check whether the user is already provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_NO_FEDERATED_USER, context);
        }
        String associatedLocalUsername =
                FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(MultitenantUtils.
                        getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Get the JIT provisioning userstore domain of the authenticated user.
     *
     * @param user         AuthenticatedUser.
     * @param tenantDomain Tenant domain.
     * @return JIT provisioning userstore domain.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private String getFederatedUserstoreDomain(AuthenticatedUser user, String tenantDomain,
                                               AuthenticationContext context)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain, context);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserstore = provisioningConfig.getProvisioningUserStore();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Setting userstore: %s as the provisioning userstore for user: %s in tenant: %s",
                    provisionedUserstore, user.getUserName(), tenantDomain));
        }
        return provisionedUserstore;
    }

    private int getOTPLength(String tenantDomain, AuthenticationContext context) throws AuthenticationFailedException {

        try {
            int otpLength = AuthenticatorConstants.DEFAULT_OTP_LENGTH;
            String configuredOTPLength = AuthenticatorUtils.getEmailAuthenticatorConfig(
                    AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_LENGTH, tenantDomain);
            if (NumberUtils.isNumber(configuredOTPLength)) {
                otpLength = Integer.parseInt(configuredOTPLength);
            }
            return otpLength;
        } catch (EmailOtpAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG,
                    context);
        }
    }

    private String getOTPCharset(String tenantDomain, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            boolean useOnlyNumericChars = Boolean.parseBoolean(
                    AuthenticatorUtils.getEmailAuthenticatorConfig(
                            AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_USE_NUMERIC_CHARS, tenantDomain));
            if (useOnlyNumericChars) {
                return AuthenticatorConstants.EMAIL_OTP_NUMERIC_CHAR_SET;
            }
            return AuthenticatorConstants.EMAIL_OTP_UPPER_CASE_ALPHABET_CHAR_SET +
                    AuthenticatorConstants.EMAIL_OTP_NUMERIC_CHAR_SET;
        } catch (EmailOtpAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG,
                    context);
        }
    }

    private boolean isBackupCodeEnabled(String tenantDomain , AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            return Boolean.parseBoolean(
                    AuthenticatorUtils.getEmailAuthenticatorConfig(
                            AuthenticatorConstants.ConnectorConfig.ENABLE_BACKUP_CODES, tenantDomain));
        } catch (EmailOtpAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG,
                    context);
        }
    }

    private String getEmailMaskingPattern(String tenantDomain, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            String regex = AuthenticatorDataHolder.getClaimMetadataManagementService().
                    getMaskingRegexForLocalClaim(AuthenticatorConstants.Claims.EMAIL_CLAIM, tenantDomain);
            if (StringUtils.isNotBlank(regex)) {
                return regex;
            }
            return AuthenticatorConstants.DEFAULT_EMAIL_MASKING_REGEX;
        } catch (ClaimMetadataException e) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_EMAIL_MASKING_REGEX, e, context,
                    tenantDomain);
        }
    }

    private long getOtpValidityPeriod(String tenantDomain, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            String value = AuthenticatorUtils.getEmailAuthenticatorConfig(
                    AuthenticatorConstants.ConnectorConfig.OTP_EXPIRY_TIME, tenantDomain);
            if (StringUtils.isBlank(value)) {
                return AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS;
            }
            long validityTime;
            try {
                validityTime = Long.parseLong(value);
            } catch (NumberFormatException e) {
                log.error(String.format("Email OTP validity period value: %s configured in tenant : %s is not a " +
                                "number. Therefore, default validity period: %s (milli-seconds) will be used", value,
                        tenantDomain, AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS));
                return AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS;
            }
            // We don't need to send tokens with infinite validity.
            if (validityTime < 0) {
                log.error(String.format("Email OTP validity period value: %s configured in tenant : %s cannot be a " +
                        "negative number. Therefore, default validity period: %s (milli-seconds) will " +
                        "be used", value, tenantDomain, AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS));
                return AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS;
            }
            // Converting to milliseconds since the config is provided in seconds.
            return validityTime * 1000;
        } catch (EmailOtpAuthenticatorServerException exception) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG,
                    exception, context);
        }
    }

    @SuppressFBWarnings("FORMAT_STRING_MANIPULATION")
    private InvalidCredentialsException handleInvalidCredentialsScenario(AuthenticatorConstants.ErrorMessages error,
                                                                         String... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, (Object) data);
        }
        if (log.isDebugEnabled()) {
            log.debug(message);
        }
        return new InvalidCredentialsException(error.getCode(), message);
    }

    private AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                  AuthenticationContext context) {

        return handleAuthErrorScenario(error, context, (Object) null);
    }

    private AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                  AuthenticationContext context, Object... data) {

        return handleAuthErrorScenario(error, null, null, data);
    }

    /**
     * Handle the scenario by returning AuthenticationFailedException which has the details of the error scenario.
     *
     * @param error     {@link AuthenticatorConstants.ErrorMessages} error message.
     * @param throwable Throwable.
     * @param data      Additional data related to the scenario.
     * @return AuthenticationFailedException.
     */
    @SuppressFBWarnings("FORMAT_STRING_MANIPULATION")
    private AuthenticationFailedException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                  Throwable throwable, AuthenticationContext context,
                                                                  Object... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, data);
        }
        String errorCode = error.getCode();

        if (context != null) {
            AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(FrameworkConstants.
                    AuthenticatorMessageType.ERROR, errorCode, message, null);
            context.setProperty(AUTHENTICATOR_MESSAGE, authenticatorMessage);
        }

        if (throwable == null) {
            return new AuthenticationFailedException(errorCode, message);
        }

        return new AuthenticationFailedException(errorCode, message, throwable);
    }

    /**
     * Generate the OTP according to the configuration parameters.
     *
     * @param tenantDomain Tenant domain.
     * @return Generated OTP.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private String generateOTP(String tenantDomain, AuthenticationContext context)
            throws AuthenticationFailedException {

        String charSet = getOTPCharset(tenantDomain, context);
        int otpLength = getOTPLength(tenantDomain, context);

        char[] chars = charSet.toCharArray();
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            sb.append(chars[rnd.nextInt(chars.length)]);
        }
        return sb.toString();
    }

    /**
     * This method is used to redirect the user to the username entering page (IDF: Identifier first).
     *
     * @param context  The authentication context
     * @param response Response
     * @throws AuthenticationFailedException
     */
    @SuppressFBWarnings("UNVALIDATED_REDIRECT")
    private void redirectUserToIDF(HttpServletResponse response, AuthenticationContext context,
                                   HttpServletRequest request) throws AuthenticationFailedException {

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String queryParams = context.getContextIdIncludedQueryParams();
        String multiOptionURI = AuthenticatorUtils.getMultiOptionURIQueryParam(request);
        try {
            log.debug("Redirecting to identifier first flow since no authenticated user was found");
            // Redirecting the user to the IDF login page.
            String redirectURL = loginPage + ("?" + queryParams) + "&" + AuthenticatorConstants.AUTHENTICATORS
                    + AuthenticatorConstants.IDF_HANDLER_NAME + ":" + AuthenticatorConstants.LOCAL_AUTHENTICATOR
                    + multiOptionURI;
            response.sendRedirect(redirectURL);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                publishInitiateAuthRedirectionDiagnosticLogs("Redirecting to identifier first flow since no " +
                        "authenticated user was found", context);
            }
        } catch (IOException e) {
            throw handleAuthErrorScenario(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_REDIRECTING_TO_IDF_PAGE , context);
        }
    }

    /**
     * This method is used to resolve the user from authentication request from identifier handler.
     *
     * @param request The httpServletRequest.
     * @param context The authentication context.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    public AuthenticatedUser resolveUser(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String username = resolveUsernameFromRequest(request);
        username = FrameworkUtils.preprocessUsername(username, context);
        AuthenticatedUser user = new AuthenticatedUser();
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);

        user.setAuthenticatedSubjectIdentifier(tenantAwareUsername);
        user.setUserName(tenantAwareUsername);
        user.setUserStoreDomain(userStoreDomain);
        user.setTenantDomain(tenantDomain);

        return user;
    }

    /**
     * This method is used to resolve the username from authentication request.
     *
     * @param request The httpServletRequest.
     * @throws AuthenticationFailedException In occasions of failing.
     */
    public String resolveUsernameFromRequest(HttpServletRequest request) throws AuthenticationFailedException {

        String identifierFromRequest = request.getParameter(AuthenticatorConstants.USER_NAME);
        if (StringUtils.isBlank(identifierFromRequest)) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_USERNAME , null);
        }
        return identifierFromRequest;
    }

    /**
     * Append the recaptcha related params if recaptcha is enabled for Email OTP.
     *
     * @param request       HttpServletRequest
     * @return string with the appended recaptcha params
     */
    private String getCaptchaParams(HttpServletRequest request, AuthenticationContext context) {

        String captchaParams = StringUtils.EMPTY;
        EmailOTPCaptchaConnector emailOTPCaptchaConnector = new EmailOTPCaptchaConnector();
        emailOTPCaptchaConnector.init(AuthenticatorDataHolder.getIdentityGovernanceService());
        try {
            if (emailOTPCaptchaConnector.isEmailRecaptchaEnabled(request) && isEmailOTPAsFirstFactor(context)) {
                captchaParams = "&reCaptcha=true";
            }
        } catch (CaptchaException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to determine if recaptcha for Email OTP is enabled", e);
            }
        }

        return captchaParams;
    }

    /**
     * This method checks if all the authentication steps up to now have been performed by authenticators that
     * implements AuthenticationFlowHandler interface. If so, it returns true.
     * AuthenticationFlowHandlers may not perform actual authentication though the authenticated user is set in the
     * context. Hence, this method can be used to determine if the user has been authenticated by a previous step.
     *
     * @param context   AuthenticationContext
     * @return true if all the authentication steps up to now have been performed by AuthenticationFlowHandlers.
     */
    private boolean isPreviousIdPAuthenticationFlowHandler(AuthenticationContext context) {

        Map<String, AuthenticatedIdPData> currentAuthenticatedIdPs = context.getCurrentAuthenticatedIdPs();
        return currentAuthenticatedIdPs != null && !currentAuthenticatedIdPs.isEmpty() &&
                currentAuthenticatedIdPs.values().stream().filter(Objects::nonNull)
                        .map(AuthenticatedIdPData::getAuthenticators).filter(Objects::nonNull)
                        .flatMap(List::stream)
                        .allMatch(authenticator ->
                                authenticator.getApplicationAuthenticator() instanceof AuthenticationFlowHandler);
    }

    private boolean isEmailOTPAsFirstFactor(AuthenticationContext context) {

        return (context.getCurrentStep() == 1 || isPreviousIdPAuthenticationFlowHandler(context));
    }

    private void publishInitiateAuthRedirectionDiagnosticLogs(String resultMessage, AuthenticationContext context) {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                EMAIL_OTP_SERVICE, INITIATE_EMAIL_OTP_REQUEST);
        diagnosticLogBuilder.resultMessage(resultMessage)
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                .inputParams(getApplicationDetails(context));
        LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
    }

    /**
     * Add application details to a map.
     *
     * @param context AuthenticationContext.
     * @return Map with application details.
     */
    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));
        return applicationDetailsMap;
    }

    /**
     * Get the user id from the authenticated user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return User id.
     */
    private Optional<String> getUserId(AuthenticatedUser authenticatedUser) {

        return Optional.ofNullable(authenticatedUser).map(user -> {
            try {
                return user.getUserId();
            } catch (UserIdNotFoundException e) {
                log.debug("Error while getting the user id from the authenticated user.", e);
                return null;
            }
        });
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
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) throws
            AuthenticationFailedException {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        String idpName = null;
        AuthenticatedUser authenticatedUserFromContext = null;
        if (context != null) {
            if (context.getExternalIdP() != null) {
                idpName = context.getExternalIdP().getIdPName();
                authenticatedUserFromContext = getAuthenticatedUserFromContext(context);
            }
            if (context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
                authenticatorData.setMessage((AuthenticatorMessage) context.getProperty(AUTHENTICATOR_MESSAGE));
            }
        }
        authenticatorData.setIdp(idpName);
        authenticatorData.setI18nKey(AuthenticatorConstants.AUTHENTICATOR_EMAIL_OTP);

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        List<String> requiredParams = new ArrayList<>();
        if ((context != null) && (authenticatedUserFromContext == null)) {
            Object propertyValue = context.getProperty(IS_USER_NAME_RESOLVED);
            if (propertyValue instanceof Boolean && !(Boolean) propertyValue) {
                setCodeMetaData(authenticatorParamMetadataList, requiredParams);
            } else {
                AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                        AuthenticatorConstants.USER_NAME, AuthenticatorConstants.DISPLAY_USER_NAME,
                        FrameworkConstants.AuthenticatorParamType.STRING, 0, Boolean.FALSE,
                        AuthenticatorConstants.USERNAME_PARAM);
                authenticatorParamMetadataList.add(usernameMetadata);
                requiredParams.add(AuthenticatorConstants.USER_NAME);
            }
        } else {
            setCodeMetaData(authenticatorParamMetadataList, requiredParams);
        }
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        authenticatorData.setRequiredParams(requiredParams);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);
        if (context != null && context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
            authenticatorData.setMessage((AuthenticatorMessage) context.getProperty(AUTHENTICATOR_MESSAGE));
        }
        return Optional.of(authenticatorData);
    }

    private static void setCodeMetaData(List<AuthenticatorParamMetadata> authenticatorParamMetadataList,
                                  List<String> requiredParams) {

        AuthenticatorParamMetadata codeMetadata = new AuthenticatorParamMetadata(
                CODE, DISPLAY_CODE, FrameworkConstants.AuthenticatorParamType.STRING,
                1, Boolean.TRUE, AuthenticatorConstants.CODE_PARAM);
        authenticatorParamMetadataList.add(codeMetadata);
        requiredParams.add(CODE);
    }

    /**
     * This method is responsible for validating whether the authenticator is supported for API Based Authentication.
     *
     * @return true if the authenticator is supported for API Based Authentication.
     */
    @Override
    public boolean isAPIBasedAuthenticationSupported() {

        return true;
    }
}
