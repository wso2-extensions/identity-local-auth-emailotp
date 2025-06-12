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

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.otp.core.constant.OTPExecutorConstants;
import org.wso2.carbon.identity.auth.otp.core.model.OTP;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.notification.NotificationConstants;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowUser;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.constant.ExecutorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.util.CommonUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.EMAIL_ADDRESS_CLAIM;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.CODE;

/**
 * Test class for EmailOTPExecutor.
 */
public class EmailOTPExecutorTest {

    public static final String SUPER_TENANT = "carbon.super";
    public static final String OTP_CODE = "123456";
    public static final String TEST_USER_EMAIL = "test@wso2.com";
    private EmailOTPExecutor emailOTPExecutor;
    private FlowExecutionContext flowExecutionContext;

    private MockedStatic<CommonUtils> commonUtilsMockedStatic;
    private MockedStatic<LoggerUtils> loggerUtilsMockedStatic;

    @BeforeMethod
    public void setUp() {

        emailOTPExecutor = new EmailOTPExecutor();
        flowExecutionContext = mock(FlowExecutionContext.class);

        commonUtilsMockedStatic = mockStatic(CommonUtils.class);
        loggerUtilsMockedStatic = mockStatic(LoggerUtils.class);
    }

    @AfterMethod
    public void tearDown() {

        commonUtilsMockedStatic.close();
        loggerUtilsMockedStatic.close();
    }

    @Test
    public void testGetName() {

        String name = emailOTPExecutor.getName();
        Assert.assertEquals(name, ExecutorConstants.EMAIL_OTP_EXECUTOR_NAME);
    }

    @Test
    public void testGetInitiationData() {

        List<String> initiationData = emailOTPExecutor.getInitiationData();
        Assert.assertTrue(initiationData.contains(EMAIL_ADDRESS_CLAIM));
        Assert.assertTrue(initiationData.contains(USERNAME_CLAIM));
    }

    @Test
    public void testGetSendOTPEventInitialOTP() {

        when(flowExecutionContext.getFlowType()).thenReturn("REGISTRATION");
        when(flowExecutionContext.getTenantDomain()).thenReturn(SUPER_TENANT);
        FlowUser flowUser = mock(FlowUser.class);
        when(flowExecutionContext.getFlowUser()).thenReturn(flowUser);
        when(flowUser.getUsername()).thenReturn("testUser");
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(TEST_USER_EMAIL);
        OTP otp = mock(OTP.class);
        when(otp.getValue()).thenReturn(OTP_CODE);
        when(otp.getGeneratedTimeInMillis()).thenReturn(System.currentTimeMillis());
        when(otp.getExpiryTimeInMillis()).thenReturn(System.currentTimeMillis() + 60000);

        Event event = emailOTPExecutor.getSendOTPEvent(OTPExecutorConstants.OTPScenarios.INITIAL_OTP,
                otp, flowExecutionContext);
        Assert.assertNotNull(event);

        Assert.assertEquals(event.getEventName(), IdentityEventConstants.Event.TRIGGER_NOTIFICATION);
        Assert.assertEquals(event.getEventProperties().get(NotificationConstants.TENANT_DOMAIN), SUPER_TENANT);
        Assert.assertEquals(event.getEventProperties().get(CODE), OTP_CODE);
        Assert.assertEquals(event.getEventProperties().get(NotificationConstants.EmailNotification.EMAIL_TEMPLATE_TYPE),
                ExecutorConstants.EMAIL_OTP_VERIFY_TEMPLATE);
        Assert.assertEquals(event.getEventProperties().get(NotificationConstants.ARBITRARY_SEND_TO), TEST_USER_EMAIL);
    }

    @Test
    public void testGetSendOTPEventResendOTP() {

        when(flowExecutionContext.getFlowType()).thenReturn("REGISTRATION");
        when(flowExecutionContext.getTenantDomain()).thenReturn(SUPER_TENANT);
        FlowUser flowUser = mock(FlowUser.class);
        when(flowExecutionContext.getFlowUser()).thenReturn(flowUser);
        when(flowUser.getUsername()).thenReturn("testUser");
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(TEST_USER_EMAIL);
        OTP otp = mock(OTP.class);
        when(otp.getValue()).thenReturn(OTP_CODE);
        when(otp.getGeneratedTimeInMillis()).thenReturn(System.currentTimeMillis());
        when(otp.getExpiryTimeInMillis()).thenReturn(System.currentTimeMillis() + 60000);

        Event event = emailOTPExecutor.getSendOTPEvent(OTPExecutorConstants.OTPScenarios.RESEND_OTP,
                otp, flowExecutionContext);
        Assert.assertNotNull(event);

        Assert.assertEquals(event.getEventName(), IdentityEventConstants.Event.TRIGGER_NOTIFICATION);
        Assert.assertEquals(event.getEventProperties().get(NotificationConstants.TENANT_DOMAIN), SUPER_TENANT);
        Assert.assertEquals(event.getEventProperties().get(CODE), OTP_CODE);
        Assert.assertEquals(event.getEventProperties().get(NotificationConstants.EmailNotification.EMAIL_TEMPLATE_TYPE),
                ExecutorConstants.EMAIL_OTP_VERIFY_TEMPLATE);
        Assert.assertEquals(event.getEventProperties().get(NotificationConstants.ARBITRARY_SEND_TO), TEST_USER_EMAIL);
    }

    @Test
    public void testHandleClaimUpdate() {

        ExecutorResponse executorResponse = new ExecutorResponse();
        FlowUser flowUser = mock(FlowUser.class);
        when(flowExecutionContext.getFlowUser()).thenReturn(flowUser);
        when(flowUser.getClaim(EMAIL_ADDRESS_CLAIM)).thenReturn(TEST_USER_EMAIL);
        emailOTPExecutor.handleClaimUpdate(flowExecutionContext, executorResponse);
        Assert.assertEquals(executorResponse.getUpdatedUserClaims().get(ExecutorConstants.EMAIL_VERIFIED_CLAIM_URI),
                true);
    }

    @DataProvider(name = "flowTypeData")
    public Object[][] flowTypeData() {
        return new Object[][] {
                { "REGISTRATION", CODE, ExecutorConstants.EMAIL_OTP_VERIFY_TEMPLATE },
                { "PASSWORD_RECOVERY",
                        AuthenticatorConstants.CONFIRMATION_CODE,
                        ExecutorConstants.EMAIL_OTP_PASSWORD_RESET_TEMPLATE },
                { "UNKNOWN_TYPE", null, null }
        };
    }

    @Test(dataProvider = "flowTypeData")
    public void testResolveFlowTypeProperties(String flowType, Object expectedCodeKey,
                                              Object expectedTemplateType) throws Exception {

        EmailOTPExecutor executor = new EmailOTPExecutor();
        Method method = EmailOTPExecutor.class.getDeclaredMethod("resolveFlowTypeProperties",
                FlowExecutionContext.class);
        method.setAccessible(true);

        FlowExecutionContext context = mock(FlowExecutionContext.class);
        when(context.getFlowType()).thenReturn(flowType);

        Object props = method.invoke(executor, context);
        Field codeKeyField = props.getClass().getDeclaredField("codeKey");
        Field templateTypeField = props.getClass().getDeclaredField("templateType");
        codeKeyField.setAccessible(true);
        templateTypeField.setAccessible(true);

        Assert.assertEquals(codeKeyField.get(props), expectedCodeKey);
        Assert.assertEquals(templateTypeField.get(props), expectedTemplateType);
    }
}
