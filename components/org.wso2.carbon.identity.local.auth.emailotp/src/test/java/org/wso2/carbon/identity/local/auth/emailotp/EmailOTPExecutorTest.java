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
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.local.auth.emailotp.constant.ExecutorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.exception.EmailOtpAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.emailotp.util.ExecutorUtils;
import org.wso2.carbon.identity.user.registration.engine.Constants;
import org.wso2.carbon.identity.user.registration.engine.exception.RegistrationEngineException;
import org.wso2.carbon.identity.user.registration.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.user.registration.engine.model.RegisteringUser;
import org.wso2.carbon.identity.user.registration.engine.model.RegistrationContext;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.local.auth.emailotp.CommonUtils.generateOTP;

/**
 * Test class for EmailOTPExecutor.
 */
public class EmailOTPExecutorTest {

    private EmailOTPExecutor emailOTPExecutor;
    private RegistrationContext registrationContext;

    private MockedStatic<CommonUtils> commonUtilsMockedStatic;
    private MockedStatic<ExecutorUtils> executorUtilsMockedStatic;
    private MockedStatic<LoggerUtils> loggerUtilsMockedStatic;

    @BeforeMethod
    public void setUp() {

        emailOTPExecutor = new EmailOTPExecutor();
        registrationContext = mock(RegistrationContext.class);

        commonUtilsMockedStatic = mockStatic(CommonUtils.class);
        executorUtilsMockedStatic = mockStatic(ExecutorUtils.class);
        loggerUtilsMockedStatic = mockStatic(LoggerUtils.class);
    }

    @AfterMethod
    public void tearDown() {

        commonUtilsMockedStatic.close();
        executorUtilsMockedStatic.close();
        loggerUtilsMockedStatic.close();
    }

    @Test
    public void testExecuteInitialRequest() throws RegistrationEngineException {

        Map<String, String> userInputData = new HashMap<>();
        when(registrationContext.getUserInputData()).thenReturn(userInputData);
        RegisteringUser registeringUser = mock(RegisteringUser.class);
        when(registrationContext.getRegisteringUser()).thenReturn(registeringUser);
        when(registeringUser.getClaim(anyString())).thenReturn(null);
        when(registeringUser.getUsername()).thenReturn(null);
        when(registrationContext.getTenantDomain()).thenReturn("carbon.super");

        commonUtilsMockedStatic.when(() -> generateOTP("carbon.super")).thenReturn("123456");
        loggerUtilsMockedStatic.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

        ExecutorResponse response = emailOTPExecutor.execute(registrationContext);
        Assert.assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_INPUT_REQUIRED);
        Assert.assertTrue(response.getRequiredData().contains(ExecutorConstants.OTP));
        Assert.assertEquals(response.getContextProperties().get(ExecutorConstants.OTP), "123456");
        Assert.assertNotNull(response.getContextProperties().get(ExecutorConstants.OTP_GENERATED_TIME));
    }

    @Test(expectedExceptions = RegistrationEngineException.class)
    public void testExecuteOTPGenerationFailure() throws RegistrationEngineException {

        Map<String, String> userInputData = new HashMap<>();
        RegisteringUser registeringUser = mock(RegisteringUser.class);
        when(registrationContext.getRegisteringUser()).thenReturn(registeringUser);
        when(registeringUser.getClaim(anyString())).thenReturn(null);
        when(registeringUser.getUsername()).thenReturn(null);
        when(registrationContext.getUserInputData()).thenReturn(userInputData);
        when(registrationContext.getTenantDomain()).thenReturn("carbon.super");

        commonUtilsMockedStatic.when(() -> generateOTP("carbon.super"))
                .thenThrow(new EmailOtpAuthenticatorServerException("OTP_GENERATION_ERROR",
                        "Error while generating OTP", new Exception("OTP generation error")));

        emailOTPExecutor.execute(registrationContext);
    }

    @Test
    public void testExecuteOTPVerificationSuccess() throws RegistrationEngineException {

        Map<String, String> userInputData = new HashMap<>();
        userInputData.put(ExecutorConstants.OTP, "123456");

        when(registrationContext.getUserInputData()).thenReturn(userInputData);
        when(registrationContext.getTenantDomain()).thenReturn("carbon.super");
        when(registrationContext.getProperty(ExecutorConstants.OTP)).thenReturn("123456");
        long validTime = System.currentTimeMillis() - (5 * 60 * 1000);
        when(registrationContext.getProperty(ExecutorConstants.OTP_GENERATED_TIME)).thenReturn(validTime);

        commonUtilsMockedStatic.when(() -> CommonUtils.getOtpValidityPeriod(anyString())).thenReturn(10L * 60 * 1000);

        ExecutorResponse response = emailOTPExecutor.execute(registrationContext);
        Assert.assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_COMPLETE);
        Assert.assertEquals(response.getContextProperties().get(ExecutorConstants.OTP), "");
    }

    @Test(expectedExceptions = RegistrationEngineException.class)
    public void testOTPGeneratedTimeNotFound() throws RegistrationEngineException {

        Map<String, String> userInputData = new HashMap<>();
        userInputData.put(ExecutorConstants.OTP, "123456");

        when(registrationContext.getUserInputData()).thenReturn(userInputData);
        when(registrationContext.getTenantDomain()).thenReturn("carbon.super");
        when(registrationContext.getProperty(ExecutorConstants.OTP)).thenReturn("123456");
        when(registrationContext.getProperty(ExecutorConstants.OTP_GENERATED_TIME)).thenReturn(null);

        emailOTPExecutor.execute(registrationContext);
    }

    @Test
    public void testExecuteExpiredOTP() throws RegistrationEngineException, EmailOtpAuthenticatorServerException {

        Map<String, String> userInputData = new HashMap<>();
        userInputData.put(ExecutorConstants.OTP, "123456");

        when(registrationContext.getUserInputData()).thenReturn(userInputData);
        when(registrationContext.getTenantDomain()).thenReturn("carbon.super");
        when(registrationContext.getProperty(ExecutorConstants.OTP)).thenReturn("123456");
        long expiredTime = System.currentTimeMillis() - (20 * 60 * 1000);
        when(registrationContext.getProperty(ExecutorConstants.OTP_GENERATED_TIME)).thenReturn(expiredTime);

        commonUtilsMockedStatic.when(() -> CommonUtils.getOtpValidityPeriod(anyString())).thenReturn(10L * 60 * 1000);

        ExecutorResponse response = emailOTPExecutor.execute(registrationContext);
        Assert.assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_RETRY);
    }

    @Test
    public void testExecuteMaxRetryCountReached() throws RegistrationEngineException {

        when(registrationContext.getProperty(ExecutorConstants.EMAIL_OTP_RETRY_COUNT)).thenReturn(3);

        ExecutorResponse response = emailOTPExecutor.execute(registrationContext);
        Assert.assertEquals(response.getResult(), Constants.ExecutorStatus.STATUS_USER_ERROR);
        Assert.assertEquals(response.getErrorMessage(), "Maximum retry count exceeded.");
    }
}
