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

package org.wso2.carbon.identity.local.auth.emailotp.constant;

import org.wso2.carbon.identity.core.util.IdentityUtil;

/**
 * Constants class.
 */
public class AuthenticatorConstants {

    private AuthenticatorConstants() {

    }

    public static final String EMAIL_OTP_AUTHENTICATOR_NAME = "email-otp-authenticator";
    public static final String EMAIL_OTP_AUTHENTICATOR_FRIENDLY_NAME = "Email OTP";
    public static final String EMAIL_AUTHENTICATOR_ERROR_PREFIX = "ETP";
    public static final String EMAIL_ADDRESS_MASKING_CHARACTER = "*";
    public static final long DEFAULT_EMAIL_OTP_VALIDITY_IN_MILLIS = 300000;
    public static final int DEFAULT_OTP_LENGTH = 6;
    public static final String DEFAULT_EMAIL_MASKING_REGEX = "(?<=.{3}).(?=[^@]*?@)";

    public static final String USERNAME_PARAM = "username.param";
    public static final String CODE_PARAM = "code.param";
    public static final String USER_PROMPT = "USER_PROMPT";
    public static final String AUTHENTICATOR_EMAIL_OTP = "authenticator.email.otp";
    public static final String PROPERTY_ACCOUNT_LOCK_ON_FAILURE = "account.lock.handler.enable";

    // OTP generation.
    public static final String EMAIL_OTP_UPPER_CASE_ALPHABET_CHAR_SET = "KIGXHOYSPRWCEFMVUQLZDNABJT";
    public static final String EMAIL_OTP_NUMERIC_CHAR_SET = "9245378016";

    public static final String RESEND = "resendCode";
    public static final String CODE = "OTPCode";
    public static final String CONFIRMATION_CODE = "confirmation-code";
    public static final String CODE_LOWERCASE = "OTPcode";
    public static final String DISPLAY_CODE = "Code";
    public static final String OTP_TOKEN = "otpToken";
    public static final String EMAIL_OTP_TEMPLATE_NAME = "EmailOTP";
    public static final String RESEND_EMAIL_OTP_TEMPLATE_NAME = "ResendEmailOTP";
    public static final String LOCAL_CLAIM_VALUE = "locale";

    public static final String CODE_MISMATCH = "codeMismatch";
    public static final String OTP_EXPIRED = "isOTPExpired";
    public static final String OTP_GENERATED_TIME = "tokenGeneratedTime";
    public static final String SERVICE_PROVIDER_NAME = "serviceProviderName";
    public static final String ACCOUNT_LOCKED = "isAccountLocked";
    public static final String BACKUP_CODES_SEPARATOR = ",";

    // OTP validation states.
    public static final String STATUS_OTP_EXPIRED = "otp-expired";
    public static final String STATUS_CODE_MISMATCH = "code-mismatch";
    public static final String STATUS_SUCCESS = "success";

    // Query params.
    public static final String AUTHENTICATORS_QUERY_PARAM = "authenticators=";
    public static final String RETRY_QUERY_PARAMS = "&authFailure=true&authFailureMsg=authentication.fail.message";
    public static final String ERROR_USER_ACCOUNT_LOCKED_QUERY_PARAMS =
            "&authFailure=true&authFailureMsg=user.account.locked";
    public static final String SCREEN_VALUE_QUERY_PARAM = "&screenValue=";
    public static final String UNLOCK_QUERY_PARAM = "&unlockTime=";
    public static final String LOCKED_REASON_QUERY_PARAM = "&lockedReason=";
    public static final String ERROR_CODE_QUERY_PARAM = "&errorCode=";
    public static final String RESEND_CODE_PARAM = "&resendCode=true";
    public static final String MULTI_OPTION_QUERY_PARAM = "multiOptionURI";
    public static final String REMAINING_NUMBER_OF_EMAIL_OTP_ATTEMPTS_QUERY = "&remainingNumberOfEmailOtpAttempts=";

    // Endpoint URLs.
    public static final String EMAIL_OTP_AUTHENTICATION_ENDPOINT_URL = "EMAILOTPAuthenticationEndpointURL";
    public static final String EMAIL_OTP_AUTHENTICATION_ERROR_PAGE_URL = "EmailOTPAuthenticationEndpointErrorPage";
    public static final String ERROR_PAGE = "authenticationendpoint/email_otp_error.do";
    public static final String EMAIL_OTP_PAGE = "authenticationendpoint/email_otp.do";

    public static final String OIDC_DIALECT_URI = "http://wso2.org/oidc/claim";
    public static final String WSO2_CLAIM_DIALECT = "http://wso2.org/claims";
    public static final String EMAIL_ATTRIBUTE_KEY = "email";
    public static final String EMAIL_OTP_EMAIL_NOT_FOUND_ERROR_CODE = "email.not.found";
    public static final String AUTHENTICATORS = "authenticators=";
    public static final String IDF_HANDLER_NAME = "IdentifierExecutor";
    public static final String LOCAL_AUTHENTICATOR = "LOCAL";
    public static final String IS_IDF_INITIATED_FROM_AUTHENTICATOR = "isIdfInitiatedFromAuthenticator";
    public static final String USER_NAME = "username";
    public static final String DISPLAY_USER_NAME = "Username";
    public static final String IS_REDIRECT_TO_EMAIL_OTP = "isRedirectToEmailOTP";
    public static final String CONF_SHOW_AUTH_FAILURE_REASON = "showAuthFailureReason";

    /**
     * Authenticator config related configurations.
     */
    public static class ConnectorConfig {

        public static final String OTP_EXPIRY_TIME = "EmailOTP.ExpiryTime";
        public static final String ENABLE_BACKUP_CODES = "EmailOTP.EnableBackupCodes";
        public static final String EMAIL_OTP_LENGTH = "EmailOTP.OTPLength";
        public static final String EMAIL_OTP_USE_ALPHANUMERIC_CHARS = "EmailOTP.UseAlphanumericChars";
        public static final String EMAIL_OTP_USE_NUMERIC_CHARS = "EmailOTP.OtpRegex.UseNumericChars";
    }

    /**
     * User claim related constants.
     */
    public static class Claims {

        public static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
        public static final String ACCOUNT_UNLOCK_TIME_CLAIM = "http://wso2.org/claims/identity/unlockTime";
        public static final String ACCOUNT_LOCKED_REASON_CLAIM = "http://wso2.org/claims/identity/lockedReason";
        public static final String OTP_BACKUP_CODES_CLAIM = "http://wso2.org/claims/identity/otpbackupcodes";
        public static final String EMAIL_OTP_FAILED_ATTEMPTS_CLAIM =
                "http://wso2.org/claims/identity/failedEmailOtpAttempts";
        public static final String LOCALE_CLAIM = IdentityUtil.getClaimUriLocale();
    }

    /**
     * Constants related to log management.
     */
    public static class LogConstants {

        public static final String EMAIL_OTP_SERVICE = "local-auth-emailotp";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String SEND_EMAIL_OTP = "send-email-otp";
            public static final String PROCESS_AUTHENTICATION_RESPONSE = "process-email-otp-authentication-response";
            public static final String INITIATE_EMAIL_OTP_REQUEST = "initiate-email-otp-authentication-request";
        }

        /**
         * Define common and reusable Input keys for diagnostic logs.
         */
        public static class InputKeys {

            private InputKeys() {
            }
            
            public static final String EMAIL_TO = "email to";
        }
    }

    /**
     * Authentication flow scenarios associated with the authenticator.
     */
    public enum AuthenticationScenarios {

        LOGOUT,
        INITIAL_OTP,
        RESEND_OTP,
        SUBMIT_OTP,
    }

    /**
     * Enum which contains the error codes and corresponding error messages.
     */
    public enum ErrorMessages {

        ERROR_CODE_ERROR_GETTING_CONFIG("65001", "Error occurred while getting the authenticator " +
                "configuration"),
        ERROR_CODE_USER_ACCOUNT_LOCKED("65002", "Account is locked for the user: %s"),
        ERROR_CODE_EMPTY_OTP_CODE("65003", "OTP token is empty for user: %s"),
        ERROR_CODE_RETRYING_OTP_RESEND("65004", "User: %s is retrying to resend the OTP"),
        ERROR_CODE_EMPTY_GENERATED_TIME("65005", "Token generated time not specified"),
        ERROR_CODE_EMPTY_OTP_CODE_IN_CONTEXT("65006", "OTP token is empty in context for user: %s"),
        ERROR_CODE_ERROR_GETTING_BACKUP_CODES("65007",
                "Error occurred while getting backup codes for user: %s"),
        ERROR_CODE_ERROR_GETTING_ACCOUNT_UNLOCK_TIME("65008",
                "Error occurred while getting account unlock time for user: %s"),
        ERROR_CODE_ERROR_UPDATING_BACKUP_CODES("65009",
                "Error occurred while updating unused backup codes for user: %s"),
        ERROR_CODE_ERROR_GETTING_EMAIL_ADDRESS("65010",
                "Error occurred while getting the email address for user: %s"),
        ERROR_CODE_ERROR_GETTING_USER_REALM("65011",
                "Error occurred while getting the user realm for tenant: %s"),
        ERROR_CODE_NO_EMAIL_FOUND("65012", "No email found for user: %s"),
        ERROR_CODE_ERROR_REDIRECTING_TO_LOGIN_PAGE("65013",
                "Error occurred while redirecting to the login page"),
        ERROR_CODE_ERROR_TRIGGERING_EVENT("65014",
                "Error occurred while triggering event: %s for the user: %s"),
        ERROR_CODE_ERROR_REDIRECTING_TO_ERROR_PAGE("65015",
                "Error occurred while redirecting to the error page"),
        ERROR_CODE_NO_USER_FOUND("65016", "No user found from the authentication steps"),
        ERROR_CODE_EMPTY_USERNAME("65017", "Username can not be empty"),
        ERROR_CODE_ERROR_GETTING_USER_STORE_MANAGER("65018",
                "Error occurred while getting the user store manager for the user: %s"),
        ERROR_CODE_GETTING_ACCOUNT_STATE("65019", "Error occurred while checking the account locked " +
                "state for the user: %s"),
        ERROR_CODE_OTP_EXPIRED("65020", "OTP expired for user: %s"),
        ERROR_CODE_OTP_INVALID("65021", "Invalid code provided by user: %s"),
        ERROR_CODE_ERROR_GETTING_EMAIL_MASKING_REGEX("65021",
                "Error occurred while getting the email masking regex from email claim in tenant: %s"),
        ERROR_CODE_ERROR_GETTING_FEDERATED_AUTHENTICATOR("65022", "Error occurred while getting IDP: " +
                "%s from tenant: %s"),
        ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR("65023", "No IDP found with the name IDP: " +
                "%s in tenant: %s"),
        ERROR_CODE_NO_CLAIM_CONFIGS_IN_FEDERATED_AUTHENTICATOR("65024", "No claim configurations " +
                "found in IDP: %s in tenant: %s"),
        ERROR_CODE_NO_EMAIL_CLAIM_MAPPINGS("65025", "No email claim mapping found in IDP: %s in " +
                "tenant: %s"),
        ERROR_CODE_NO_FEDERATED_USER("65026", "No federated user found"),
        ERROR_CODE_NO_AUTHENTICATED_USER("65027", "No authenticated user found"),
        ERROR_CODE_ERROR_REDIRECTING_TO_IDF_PAGE("65028", "Error while redirecting to the login page."),
        ERROR_CODE_ERROR_GETTING_AUTHENTICATED_USER("65029",
                "Error occurred while getting the authenticated user.");


        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return EMAIL_AUTHENTICATOR_ERROR_PREFIX + "-" + code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return code + " - " + message;
        }
    }
}
