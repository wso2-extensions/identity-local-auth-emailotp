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

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.internal.AuthenticatorDataHolder;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_LENGTH;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_USE_ALPHANUMERIC_CHARS;

public class CommonUtilsTest {

    private static final String SUPER_TENANT = "carbon.super";

    @Test
    public void testGenerateOTP() throws IdentityGovernanceException {

        try (MockedStatic<AuthenticatorDataHolder> dataHolderMockedStatic =
                     Mockito.mockStatic(AuthenticatorDataHolder.class)) {
            Map<String, String> configValues = new HashMap<>();
            configValues.put(EMAIL_OTP_USE_ALPHANUMERIC_CHARS, "true");
            configValues.put(EMAIL_OTP_LENGTH, "6");
            mockGovernanceService(configValues, dataHolderMockedStatic);
            String otp = CommonUtils.generateOTP(SUPER_TENANT);
            assertNotNull(otp, "Generated OTP should not be null.");
            assertEquals(otp.length(), 6);
        }
    }

    @Test
    public void testGetOTPLength() throws IdentityGovernanceException {

        try (MockedStatic<AuthenticatorDataHolder> dataHolderMockedStatic = mockStatic(AuthenticatorDataHolder.class)) {
            Map<String, String> configValues = new HashMap<>();
            configValues.put(EMAIL_OTP_LENGTH, "6");
            mockGovernanceService(configValues, dataHolderMockedStatic);
            int otpLength = CommonUtils.getOTPLength(SUPER_TENANT);
            assertEquals(otpLength, 6, "OTP length should be 6.");
        }
    }

    @Test
    public void testGetOTPCharset() throws IdentityGovernanceException {

        try (MockedStatic<AuthenticatorDataHolder> dataHolderMockedStatic = mockStatic(AuthenticatorDataHolder.class)) {
            Map<String, String> configValues = new HashMap<>();
            configValues.put(EMAIL_OTP_USE_ALPHANUMERIC_CHARS, "true");
            mockGovernanceService(configValues, dataHolderMockedStatic);
            String otpCharset = CommonUtils.getOTPCharset(SUPER_TENANT);
            assertNotNull(otpCharset, "OTP charset should not be null.");
        }
    }

    @Test
    public void testGetOtpValidityPeriod() throws IdentityGovernanceException {

        try (MockedStatic<AuthenticatorDataHolder> dataHolderMockedStatic = mockStatic(AuthenticatorDataHolder.class)) {
            Map<String, String> configValues = new HashMap<>();
            configValues.put(AuthenticatorConstants.ConnectorConfig.OTP_EXPIRY_TIME, "60");
            mockGovernanceService(configValues, dataHolderMockedStatic);
            long validityPeriod = CommonUtils.getOtpValidityPeriod(SUPER_TENANT);
            assertEquals(validityPeriod, 60000, "OTP validity period should be 60000 ms.");
        }
    }

    @Test
    public void testGetEmailAuthenticatorConfig() throws IdentityGovernanceException {

        try (MockedStatic<AuthenticatorDataHolder> dataHolderMockedStatic = mockStatic(AuthenticatorDataHolder.class)) {
            mockGovernanceService(Collections.singletonMap(EMAIL_OTP_LENGTH, "6"), dataHolderMockedStatic);
            String otpLength = CommonUtils.getEmailAuthenticatorConfig(EMAIL_OTP_LENGTH, SUPER_TENANT);
            assertNotNull(otpLength, "OTP length should not be null.");
            assertEquals(otpLength, "6", "OTP length should be 6.");
        }
    }

    private void mockGovernanceService(Map<String, String> configValues,
                                       MockedStatic<AuthenticatorDataHolder> dataHolderMockedStatic)
            throws IdentityGovernanceException {

        IdentityGovernanceService identityGovernanceService = mock(IdentityGovernanceService.class);
        for (int i = 0; i < configValues.size(); i++) {
            Property[] properties = new Property[1];
            String configName = (String) configValues.keySet().toArray()[i];
            String configValue = configValues.get(configName);
            Property property = new Property();
            property.setName(configName);
            property.setValue(configValue);
            properties[0] = property;
            when(identityGovernanceService.getConfiguration(new String[]{configName},
                    SUPER_TENANT)).thenReturn(properties);
        }
        dataHolderMockedStatic.when(AuthenticatorDataHolder::getIdentityGovernanceService)
                .thenReturn(identityGovernanceService);
    }
}
