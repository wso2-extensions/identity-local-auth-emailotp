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

package org.wso2.carbon.identity.local.auth.emailotp.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.notification.NotificationConstants;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.internal.AuthenticatorDataHolder;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.local.auth.emailotp.constant.ExecutorConstants.TENANT_DOMAIN;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.ExecutorConstants.USER_NAME;

/**
 * Utility class for executor operations.
 */
public class ExecutorUtils {

    private ExecutorUtils() {

    }

    public static void triggerEvent(String eventName, Map<String, Object> metaProperties)
            throws IdentityEventException {

        String username = String.valueOf(metaProperties.remove(USER_NAME));
        String tenantDomain = String.valueOf(metaProperties.remove(TENANT_DOMAIN));

        // Event properties.
        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put(NotificationConstants.FLOW_TYPE, NotificationConstants.REGISTRATION_FLOW);

        for (Map.Entry<String, Object> metaProperty : metaProperties.entrySet()) {
            if (StringUtils.isNotBlank(metaProperty.getKey()) && metaProperty.getValue() != null) {
                properties.put(metaProperty.getKey(), metaProperty.getValue());
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        String receiver = (String) properties.get("send-to");
        if (LoggerUtils.isDiagnosticLogsEnabled() && eventName.equals(IdentityEventConstants.Event
                .TRIGGER_NOTIFICATION)) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    AuthenticatorConstants.LogConstants.EMAIL_OTP_SERVICE,
                    AuthenticatorConstants.LogConstants.ActionIDs.SEND_EMAIL_OTP);
            diagnosticLogBuilder
                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(username) : username)
                    .inputParam(LogConstants.InputKeys.TENANT_DOMAIN, tenantDomain)
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
    }
}
