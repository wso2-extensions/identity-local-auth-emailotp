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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.exception.EmailOtpAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.emailotp.internal.AuthenticatorDataHolder;
import org.wso2.carbon.identity.local.auth.emailotp.util.AuthenticatorUtils;

import java.security.SecureRandom;

/**
 * Common utility functions for Email OTP Authenticator and Email OTP Executor.
 */
public class CommonUtils {

    private static final Log LOG = LogFactory.getLog(CommonUtils.class);

    private CommonUtils() {

    }

    /**
     * Generate OTP.
     *
     * @param tenantDomain Tenant domain.
     * @return Generated OTP.
     * @throws EmailOtpAuthenticatorServerException Email OTP Authenticator Server Exception.
     */
    protected static String generateOTP(String tenantDomain) throws EmailOtpAuthenticatorServerException {

        String charSet = getOTPCharset(tenantDomain);
        int otpLength = getOTPLength(tenantDomain);

        char[] chars = charSet.toCharArray();
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < otpLength; i++) {
            sb.append(chars[rnd.nextInt(chars.length)]);
        }
        return sb.toString();
    }

    protected static int getOTPLength(String tenantDomain) throws EmailOtpAuthenticatorServerException {

        int otpLength = AuthenticatorConstants.DEFAULT_OTP_LENGTH;
        String configuredOTPLength = AuthenticatorUtils.getEmailAuthenticatorConfig(
                AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_LENGTH, tenantDomain);
        if (NumberUtils.isNumber(configuredOTPLength)) {
            otpLength = Integer.parseInt(configuredOTPLength);
        }
        return otpLength;
    }

    private static String getOTPCharset(String tenantDomain) throws EmailOtpAuthenticatorServerException {

        boolean useAlphanumericChars = Boolean.parseBoolean(
                AuthenticatorUtils.getEmailAuthenticatorConfig(
                        AuthenticatorConstants.ConnectorConfig.EMAIL_OTP_USE_ALPHANUMERIC_CHARS, tenantDomain));
        if (useAlphanumericChars) {
            return AuthenticatorConstants.EMAIL_OTP_UPPER_CASE_ALPHABET_CHAR_SET +
                    AuthenticatorConstants.EMAIL_OTP_NUMERIC_CHAR_SET;
        }
        return AuthenticatorConstants.EMAIL_OTP_NUMERIC_CHAR_SET;
    }

    /**
     * Get the email masking pattern.
     *
     * @param tenantDomain Tenant domain.
     * @return Email masking pattern.
     * @throws ClaimMetadataException Claim Metadata Exception.
     */
    protected static String getEmailMaskingPattern(String tenantDomain) throws ClaimMetadataException {

        String regex = AuthenticatorDataHolder.getClaimMetadataManagementService().
                getMaskingRegexForLocalClaim(AuthenticatorConstants.Claims.EMAIL_CLAIM, tenantDomain);
        if (StringUtils.isNotBlank(regex)) {
            return regex;
        }
        return AuthenticatorConstants.DEFAULT_EMAIL_MASKING_REGEX;
    }

    /**
     * Get the OTP validity period.
     *
     * @param tenantDomain Tenant domain.
     * @return OTP validity period.
     * @throws EmailOtpAuthenticatorServerException Email OTP Authenticator Server Exception.
     */
    public static long getOtpValidityPeriod(String tenantDomain)
            throws EmailOtpAuthenticatorServerException {

        String value = AuthenticatorUtils.getEmailAuthenticatorConfig(
                AuthenticatorConstants.ConnectorConfig.OTP_EXPIRY_TIME, tenantDomain);
        if (StringUtils.isBlank(value)) {
            return AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS;
        }
        long validityTime;
        try {
            validityTime = Long.parseLong(value);
        } catch (NumberFormatException e) {
            LOG.error(String.format("Email OTP validity period value: %s configured in tenant : %s is not a " +
                            "number. Therefore, default validity period: %s (milli-seconds) will be used", value,
                    tenantDomain, AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS));
            return AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS;
        }
        // We don't need to send tokens with infinite validity.
        if (validityTime < 0) {
            LOG.error(String.format("Email OTP validity period value: %s configured in tenant : %s cannot be a " +
                    "negative number. Therefore, default validity period: %s (milli-seconds) will " +
                    "be used", value, tenantDomain, AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS));
            return AuthenticatorConstants.DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS;
        }
        // Converting to milliseconds since the config is provided in seconds.
        return validityTime * 1000;
    }
}
