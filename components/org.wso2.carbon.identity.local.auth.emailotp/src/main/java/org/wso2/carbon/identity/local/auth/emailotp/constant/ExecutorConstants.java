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

package org.wso2.carbon.identity.local.auth.emailotp.constant;

/**
 * Constants for the executor.
 */
public class ExecutorConstants {

    private ExecutorConstants() {

    }

    public static final String EMAIL_OTP_EXECUTOR_NAME = "EmailOTPExecutor";
    public static final String EMAIL_OTP_VERIFY_TEMPLATE = "EmailOTPVerification";
    public static final String EMAIL_OTP_PASSWORD_RESET_TEMPLATE = "passwordResetOTP";
    public static final String EMAIL_VERIFIED_CLAIM_URI = "http://wso2.org/claims/identity/emailVerified";
    public static final String VERIFIED_EMAIL_ADDRESSES_CLAIM_URI = "http://wso2.org/claims/verifiedEmailAddresses";
}
