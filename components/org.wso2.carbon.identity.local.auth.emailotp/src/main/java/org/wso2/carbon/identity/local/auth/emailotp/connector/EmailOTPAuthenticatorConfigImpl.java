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

package org.wso2.carbon.identity.local.auth.emailotp.connector;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * This class contains the authenticator config implementation.
 */
public class EmailOTPAuthenticatorConfigImpl implements IdentityConnectorConfig {


    @Override
    public String getName() {

        return AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return AuthenticatorConstants.EMAIL_OTP_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {

        return "Multi Factor Authenticators";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(AuthenticatorConstants.ConnectorConfig.OTP_EXPIRY_TIME, "Email OTP expiry time");
        nameMapping.put(AuthenticatorConstants.ConnectorConfig.ENABLE_BACKUP_CODES, "Enable authenticate with backup codes");
        nameMapping.put(AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_LENGTH, "Email OTP token length");
        nameMapping.put(AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_USE_NUMERIC_CHARS, "Use only numeric characters for OTP token");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(AuthenticatorConstants.ConnectorConfig.OTP_EXPIRY_TIME, "Email OTP expiry time in seconds");
        descriptionMapping.put(AuthenticatorConstants.ConnectorConfig.ENABLE_BACKUP_CODES, "Allow users to login with backup codes");
        descriptionMapping.put(AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_LENGTH, "Number of characters in the OTP token");
        descriptionMapping.put(AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_USE_NUMERIC_CHARS, "Enabling this will only generate OTP tokens with 0-9 " +
                "characters");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(AuthenticatorConstants.ConnectorConfig.OTP_EXPIRY_TIME);
        properties.add(AuthenticatorConstants.ConnectorConfig.ENABLE_BACKUP_CODES);
        properties.add(AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_LENGTH);
        properties.add(AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_USE_NUMERIC_CHARS);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {

        // 5 minutes in seconds.
        String otpExpiryTime = "300";
        String useBackupCodes = "false";
        String useNumericChars = "true";
        String otpLength = Integer.toString(AuthenticatorConstants.DEFAULT_OTP_LENGTH);

        String otpExpiryTimeProperty = IdentityUtil.getProperty(AuthenticatorConstants.ConnectorConfig.OTP_EXPIRY_TIME);
        String useBackupCodesProperty = IdentityUtil.getProperty(
                AuthenticatorConstants.ConnectorConfig.ENABLE_BACKUP_CODES);
        String useNumericCharsProperty = IdentityUtil.getProperty(
                AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_USE_NUMERIC_CHARS);
        String otpLengthProperty = IdentityUtil.getProperty(AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_LENGTH);

        if (StringUtils.isNotBlank(otpExpiryTimeProperty)) {
            otpExpiryTime = otpExpiryTimeProperty;
        }
        if (StringUtils.isNotBlank(useBackupCodesProperty)) {
            useBackupCodes = useBackupCodesProperty;
        }
        if (StringUtils.isNotBlank(useNumericCharsProperty)) {
            useNumericChars = useNumericCharsProperty;
        }
        if (StringUtils.isNotBlank(otpLengthProperty)) {
            otpLength = otpLengthProperty;
        }
        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(AuthenticatorConstants.ConnectorConfig.OTP_EXPIRY_TIME, otpExpiryTime);
        defaultProperties.put(AuthenticatorConstants.ConnectorConfig.ENABLE_BACKUP_CODES, useBackupCodes);
        defaultProperties.put(AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_USE_NUMERIC_CHARS, useNumericChars);
        defaultProperties.put(AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_LENGTH, otpLength);

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {

        return null;
    }
}
