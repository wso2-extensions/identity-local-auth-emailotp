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

import org.wso2.carbon.identity.auth.otp.core.AbstractOTPExecutor;
import org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.notification.NotificationConstants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.constant.ExecutorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.util.CommonUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.CODE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.CONFIRMATION_CODE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.LogConstants.EMAIL_OTP_SERVICE;

/**
 * Email OTP executor for user registration.
 */
public class EmailOTPExecutor extends AbstractOTPExecutor {

    @Override
    public String getName() {

        return ExecutorConstants.EMAIL_OTP_EXECUTOR_NAME;
    }

    @Override
    public List<String> getInitiationData() {

        List<String> initiationData = new ArrayList<>();
        initiationData.add(EMAIL_ADDRESS_CLAIM);
        initiationData.add(USERNAME_CLAIM);
        return initiationData;
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext flowExecutionContext) throws FlowEngineException {

        return null;
    }

    @Override
    protected Event getSendOTPEvent(OTPExecutorConstants.OTPScenarios scenario, OTP otp, FlowExecutionContext context) {

        FlowTypeProperties flowProperties = resolveFlowTypeProperties(context);
        String tenantDomain = context.getTenantDomain();
        String email = String.valueOf(context.getFlowUser().getClaim(EMAIL_ADDRESS_CLAIM));

        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(flowProperties.codeKey, otp.getValue());
        eventProperties.put(NotificationConstants.EmailNotification.EMAIL_TEMPLATE_TYPE, flowProperties.templateType);
        eventProperties.put(NotificationConstants.ARBITRARY_SEND_TO, email);
        eventProperties.put(NotificationConstants.TENANT_DOMAIN, tenantDomain);

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    EMAIL_OTP_SERVICE, AuthenticatorConstants.LogConstants.ActionIDs.SEND_EMAIL_OTP);
            diagnosticLogBuilder.resultMessage("Email OTP sent successfully.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .inputParam(LogConstants.InputKeys.SUBJECT, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(email) : email)
                    .inputParam("scenario", scenario.name());
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return new Event(IdentityEventConstants.Event.TRIGGER_NOTIFICATION, eventProperties);
    }

    @Override
    protected long getOTPValidityPeriod(String tenantDomain) throws FlowEngineException {

        try {
            return CommonUtils.getOtpValidityPeriod(tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw handleAuthErrorScenario(e, "Error occurred while getting OTP validity period.");
        }
    }

    @Override
    protected int getMaxRetryCount(FlowExecutionContext flowExecutionContext) {

        return 3;
    }

    @Override
    protected int getMaxResendCount(FlowExecutionContext flowExecutionContext) {

        return 3;
    }

    @Override
    protected void handleClaimUpdate(FlowExecutionContext flowExecutionContext, ExecutorResponse executorResponse) {

        Map<String, Object> updatedClaims = new HashMap<>();
        updatedClaims.put(ExecutorConstants.EMAIL_VERIFIED_CLAIM_URI, true);
        updatedClaims.put(ExecutorConstants.VERIFIED_EMAIL_ADDRESSES_CLAIM_URI,
                flowExecutionContext.getFlowUser().getClaim(EMAIL_ADDRESS_CLAIM));
        executorResponse.setUpdatedUserClaims(updatedClaims);
    }

    @Override
    protected int getOTPLength(String tenantDomain) throws FlowEngineException {

        try {
            return CommonUtils.getOTPLength(tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw handleAuthErrorScenario(e, "Error occurred while getting OTP length.");
        }
    }

    @Override
    protected String getOTPCharset(String tenantDomain) throws FlowEngineException {

        try {
            return CommonUtils.getOTPCharset(tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw handleAuthErrorScenario(e, "Error occurred while getting OTP charset.");
        }
    }

    @Override
    protected String getPostOTPGeneratedEventName() {

        return IdentityEventConstants.Event.POST_GENERATE_EMAIL_OTP;
    }

    @Override
    protected String getPostOTPValidatedEventName() {

        return IdentityEventConstants.Event.POST_VALIDATE_EMAIL_OTP;
    }

    @Override
    protected String getDiagnosticLogComponentId() {

        return EMAIL_OTP_SERVICE;
    }

    private FlowTypeProperties resolveFlowTypeProperties(FlowExecutionContext flowExecutionContext) {

        switch (flowExecutionContext.getFlowType()) {
            case "REGISTRATION":
                return new FlowTypeProperties(CODE, ExecutorConstants.EMAIL_OTP_VERIFY_TEMPLATE);
            case "PASSWORD_RECOVERY":
                return new FlowTypeProperties(CONFIRMATION_CODE, ExecutorConstants.EMAIL_OTP_PASSWORD_RESET_TEMPLATE);
            default:
                return new FlowTypeProperties(null, null);
        }
    }

    private static class FlowTypeProperties {

        final String codeKey;
        final String templateType;

        FlowTypeProperties(String codeKey, String templateType) {
            this.codeKey = codeKey;
            this.templateType = templateType;
        }
    }
}
