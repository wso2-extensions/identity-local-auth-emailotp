/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.local.auth.emailotp;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.constant.ExecutorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.exception.EmailOtpAuthenticatorServerException;
import org.wso2.carbon.identity.user.registration.engine.Constants;
import org.wso2.carbon.identity.user.registration.engine.exception.RegistrationEngineException;
import org.wso2.carbon.identity.user.registration.engine.exception.RegistrationEngineServerException;
import org.wso2.carbon.identity.user.registration.engine.graph.Executor;
import org.wso2.carbon.identity.user.registration.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.user.registration.engine.model.RegistrationContext;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.event.handler.notification.NotificationConstants.ARBITRARY_SEND_TO;
import static org.wso2.carbon.identity.event.handler.notification.NotificationConstants.EmailNotification.EMAIL_TEMPLATE_TYPE;
import static org.wso2.carbon.identity.local.auth.emailotp.CommonUtils.generateOTP;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.CODE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.LogConstants.EMAIL_OTP_SERVICE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.RESEND;
import static org.wso2.carbon.identity.local.auth.emailotp.util.ExecutorUtils.triggerEvent;
import static org.wso2.carbon.identity.user.registration.engine.Constants.ExecutorStatus.STATUS_USER_ERROR;
import static org.wso2.carbon.identity.user.registration.engine.Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED;

/**
 * Email OTP Executor.
 */
public class EmailOTPExecutor implements Executor {

    @Override
    public String getName() {

        return ExecutorConstants.EMAIL_OTP_EXECUTOR_NAME;
    }

    @Override
    public ExecutorResponse execute(RegistrationContext registrationContext) throws RegistrationEngineException {

        ExecutorResponse executorResponse = new ExecutorResponse();
        Map<String, Object> contextProperties = new HashMap<>();
        executorResponse.setContextProperty(contextProperties);

        handleRetryCount(registrationContext, executorResponse);
        if (STATUS_USER_ERROR.equals(executorResponse.getResult())) {
            return executorResponse;
        }

        // Null OTP indicates the initial node execution. Therefore, OTP should be requested from the user.
        // Further, the executor should trigger the email sending logic.
        if (isInitiateRequest(registrationContext)) {
            initiateEmailOTPRegistration(registrationContext, executorResponse);
        } else {
            processEmailOTPRegistration(registrationContext, executorResponse);
        }
        handleRetry(registrationContext, executorResponse);
        return executorResponse;
    }

    @Override
    public List<String> getInitiationData() {

        List<String> initiationData = new ArrayList<>();
        initiationData.add(EMAIL_ADDRESS_CLAIM);
        initiationData.add(USERNAME_CLAIM);
        return initiationData;
    }

    private boolean isInitiateRequest(RegistrationContext registrationContext) {

        return registrationContext.getUserInputData().get(ExecutorConstants.OTP) == null;
    }

    private void handleRetryCount(RegistrationContext registrationContext, ExecutorResponse executorResponse) {

        // To maintain the max retry attempts, the executor should maintain a counter in the context properties.
        if (registrationContext.getProperty(ExecutorConstants.EMAIL_OTP_RETRY_COUNT) != null) {

            int retryCount = (int) registrationContext.getProperty(ExecutorConstants.EMAIL_OTP_RETRY_COUNT);
            // TODO: Configurable max retry count.
            if (retryCount >= 3) {
                executorResponse.setResult(Constants.ExecutorStatus.STATUS_USER_ERROR);
                executorResponse.setErrorMessage("Maximum retry count exceeded.");
            }
            executorResponse.getContextProperties().put(ExecutorConstants.EMAIL_OTP_RETRY_COUNT, retryCount + 1);
            return;
        }
        executorResponse.getContextProperties().put(ExecutorConstants.EMAIL_OTP_RETRY_COUNT, 1);
    }

    private void initiateEmailOTPRegistration(RegistrationContext context, ExecutorResponse executorResponse) {

        executorResponse.setResult(STATUS_USER_INPUT_REQUIRED);
        List<String> requiredData = new ArrayList<>();
        requiredData.add(ExecutorConstants.OTP);
        sendEmailOTP(AuthenticatorConstants.AuthenticationScenarios.INITIAL_OTP, context,
                executorResponse);
        executorResponse.setRequiredData(requiredData);
    }

    private void processEmailOTPRegistration(RegistrationContext registrationContext,
                                             ExecutorResponse executorResponse) throws RegistrationEngineException {
        try {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        EMAIL_OTP_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
                diagnosticLogBuilder.resultMessage("Processing email otp verification response.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            // OTP is provided by the user. Therefore, the executor should validate the OTP.
            // If the OTP is valid, the executor should return the success status.
            // If the OTP is invalid, the executor should return an error status.
            // The executor should maintain the OTP in the context properties to validate the OTP.
            String otp = registrationContext.getUserInputData().get(ExecutorConstants.OTP);
            if (StringUtils.isBlank(otp)) {
                executorResponse.setResult(Constants.ExecutorStatus.STATUS_RETRY);
            }
            String contextOtp = (String) registrationContext.getProperty(ExecutorConstants.OTP);
            if (contextOtp == null) {
                executorResponse.setResult(Constants.ExecutorStatus.STATUS_ERROR);
                executorResponse.setErrorMessage("OTP is not generated.");
                return;
            }
            boolean isOtpExpired = isOtpExpired(registrationContext.getTenantDomain(), registrationContext);
            if (otp.equals(contextOtp)) {
                if (isOtpExpired) {
                    executorResponse.setResult(Constants.ExecutorStatus.STATUS_RETRY);
                    registrationContext.setProperty(ExecutorConstants.OTP_EXPIRED, true);
                } else {
                    executorResponse.setResult(Constants.ExecutorStatus.STATUS_COMPLETE);
                    executorResponse.getContextProperties().put(ExecutorConstants.OTP_EXPIRED, false);
                    executorResponse.getContextProperties().put(ExecutorConstants.OTP_GENERATED_TIME,
                            StringUtils.EMPTY);
                    executorResponse.getContextProperties().put(ExecutorConstants.OTP, StringUtils.EMPTY);
                    Map<String, Object> updatedClaims = new HashMap<>();
                    updatedClaims.put(ExecutorConstants.EMAIL_VERIFIED_CLAIM_URI, true);
                    executorResponse.setUpdatedUserClaims(updatedClaims);
                }
            } else {
                executorResponse.setResult(Constants.ExecutorStatus.STATUS_RETRY);
            }
        } catch (EmailOtpAuthenticatorServerException e) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        EMAIL_OTP_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
                diagnosticLogBuilder.resultMessage("Error occurred while processing email otp authentication response.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG, e,
                    registrationContext);
        }
    }

    /**
     * Checks whether otp is Expired or not.
     *
     * @param tenantDomain Tenant domain.
     * @param context      Authentication Context.
     */
    private boolean isOtpExpired(String tenantDomain, RegistrationContext context)
            throws RegistrationEngineException, EmailOtpAuthenticatorServerException {

        if (context.getProperty(AuthenticatorConstants.OTP_GENERATED_TIME) == null) {
            throw handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages.ERROR_CODE_EMPTY_GENERATED_TIME, null,
                    context);
        }
        long generatedTime = (long) context.getProperty(AuthenticatorConstants.OTP_GENERATED_TIME);
        long expireTime = CommonUtils.getOtpValidityPeriod(tenantDomain);
        return System.currentTimeMillis() >= generatedTime + expireTime;
    }

    private void sendEmailOTP(AuthenticatorConstants.AuthenticationScenarios scenario, RegistrationContext context,
                              ExecutorResponse executorResponse) {

        try {
            Map<String, Object> contextProperties = executorResponse.getContextProperties();
            String tenantDomain = context.getTenantDomain();
            String email = String.valueOf(context.getUserInputData().get(EMAIL_ADDRESS_CLAIM));
            String username = String.valueOf(context.getUserInputData().get(USERNAME_CLAIM));

            // Generate OTP.
            String otp = generateOTP(tenantDomain);
            contextProperties.put(ExecutorConstants.OTP, otp);
            contextProperties.put(ExecutorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
            contextProperties.put(ExecutorConstants.OTP_EXPIRED, false);
            publishPostEmailOTPGeneratedEvent(context);

            int otpLength = CommonUtils.getOTPLength(tenantDomain);
            Map<String, String> additionalInfo = new HashMap<>();
            additionalInfo.put(ExecutorConstants.OTP_LENGTH, String.valueOf(otpLength));
            executorResponse.setAdditionalInfo(additionalInfo);

            Map<String, Object> metaProperties = new HashMap<>();
            metaProperties.put(CODE, otp);
            metaProperties.put(EMAIL_TEMPLATE_TYPE, ExecutorConstants.EMAIL_OTP_VERIFY_TEMPLATE);
            metaProperties.put(ARBITRARY_SEND_TO, email);
            metaProperties.put(ExecutorConstants.TENANT_DOMAIN, tenantDomain);
            triggerEvent(IdentityEventConstants.Event.TRIGGER_NOTIFICATION, metaProperties);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        EMAIL_OTP_SERVICE, AuthenticatorConstants.LogConstants.ActionIDs.SEND_EMAIL_OTP);
                diagnosticLogBuilder.resultMessage("Email OTP sent successfully.")
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                                LoggerUtils.getMaskedContent(username) : username)
                        .inputParam("scenario", scenario.name());
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (EmailOtpAuthenticatorServerException | IdentityEventException e) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        EMAIL_OTP_SERVICE, AuthenticatorConstants.LogConstants.ActionIDs.SEND_EMAIL_OTP);
                diagnosticLogBuilder.resultMessage("Error occurred while sending email OTP.")
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .inputParam("scenario", scenario.name());
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }

        }
    }

    private void handleRetry(RegistrationContext context, ExecutorResponse executorResponse) {

        if (executorResponse.getResult().equals(Constants.ExecutorStatus.STATUS_RETRY)) {
            Object isOTPExpiredObj = context.getProperty(ExecutorConstants.OTP_EXPIRED);
            if (isOTPExpiredObj != null && (boolean) isOTPExpiredObj) {
                sendEmailOTP(AuthenticatorConstants.AuthenticationScenarios.RESEND_OTP, context,
                        executorResponse);
                executorResponse.setResult(Constants.ExecutorStatus.STATUS_RETRY);
                executorResponse.setErrorMessage("OTP expired. Please try again.");
                return;
            }
            executorResponse.getContextProperties().put(AuthenticatorConstants.RESEND, true);
            executorResponse.setErrorMessage("Invalid OTP. Please try again.");
        }
    }

    /**
     * Trigger event after generating Email OTP.
     *
     * @param context Registration context.
     */
    private void publishPostEmailOTPGeneratedEvent(RegistrationContext context)
            throws EmailOtpAuthenticatorServerException, IdentityEventException {

        String tenantDomain = context.getTenantDomain();
        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(IdentityEventConstants.EventProperty.CORRELATION_ID, context.getCorrelationId());
        String resendCode = String.valueOf(context.getProperty(RESEND));
        if (StringUtils.isNotBlank(resendCode)) {
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE, resendCode);
        } else {
            eventProperties.put(IdentityEventConstants.EventProperty.RESEND_CODE, false);
        }
        // Add OTP generated time and OTP expiry time to the event.
        Object otpGeneratedTimeProperty = context.getProperty(AuthenticatorConstants.OTP_GENERATED_TIME);
        if (otpGeneratedTimeProperty != null) {
            long otpGeneratedTime = (long) otpGeneratedTimeProperty;
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_GENERATED_TIME, otpGeneratedTime);

            // Calculate OTP expiry time.
            long expiryTime = otpGeneratedTime + CommonUtils.getOtpValidityPeriod(tenantDomain);
            eventProperties.put(IdentityEventConstants.EventProperty.OTP_EXPIRY_TIME, expiryTime);
        }
        triggerEvent(IdentityEventConstants.Event.POST_GENERATE_EMAIL_OTP, eventProperties);
    }

    /**
     * Handle the scenario by returning RegistrationEngineServerException which has the details of the error scenario.
     *
     * @param error     {@link AuthenticatorConstants.ErrorMessages} error message.
     * @param throwable Throwable.
     * @param data      Additional data related to the scenario.
     * @return RegistrationEngineServerException.
     */
    @SuppressFBWarnings("FORMAT_STRING_MANIPULATION")
    private RegistrationEngineServerException handleAuthErrorScenario(AuthenticatorConstants.ErrorMessages error,
                                                                      Throwable throwable, RegistrationContext context,
                                                                      Object... data) {

        String message = error.getMessage();
        if (data != null) {
            message = String.format(message, data);
        }
        String errorCode = error.getCode();
        return new RegistrationEngineServerException(errorCode, message, "Error occurred in the email OTP executor",
                throwable);
    }
}
