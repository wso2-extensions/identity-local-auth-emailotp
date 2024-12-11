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

package org.wso2.carbon.identity.local.auth.emailotp.util;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.identity.local.auth.emailotp.exception.EmailOtpAuthenticatorServerException;
import org.wso2.carbon.identity.local.auth.emailotp.internal.AuthenticatorDataHolder;

import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.EMAIL_OTP_AUTHENTICATION_ENDPOINT_URL;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.EMAIL_OTP_AUTHENTICATION_ERROR_PAGE_URL;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.EMAIL_OTP_PAGE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.ERROR_PAGE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.ErrorMessages.ERROR_CODE_GETTING_ACCOUNT_STATE;
import static org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants.MULTI_OPTION_QUERY_PARAM;

/**
 * This class contains the utility method implementations.
 */
public class AuthenticatorUtils {

    /**
     * Check whether a given user account is locked.
     *
     * @param user Authenticated user.
     * @return True if user account is locked.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    @SuppressFBWarnings("FORMAT_STRING_MANIPULATION")
    public static boolean isAccountLocked(AuthenticatedUser user) throws AuthenticationFailedException {

        try {
            return AuthenticatorDataHolder.getAccountLockService().isAccountLocked(user.getUserName(),
                    user.getTenantDomain(), user.getUserStoreDomain());
        } catch (AccountLockServiceException e) {
            String error = String.format(ERROR_CODE_GETTING_ACCOUNT_STATE.getMessage(), user.getUserName());
            throw new AuthenticationFailedException(ERROR_CODE_GETTING_ACCOUNT_STATE.getCode(), error, e);
        }
    }

    /**
     * Get email authenticator config related to the given key.
     *
     * @param key          Authenticator config key.
     * @param tenantDomain Tenant domain.
     * @return Value associated with the given config key.
     * @throws EmailOtpAuthenticatorServerException If an error occurred while getting th config value.
     */
    public static String getEmailAuthenticatorConfig(String key, String tenantDomain)
            throws EmailOtpAuthenticatorServerException {

        try {
            Property[] connectorConfigs;
            IdentityGovernanceService governanceService = AuthenticatorDataHolder.getIdentityGovernanceService();
            connectorConfigs = governanceService.getConfiguration(new String[]{key}, tenantDomain);
            return connectorConfigs[0].getValue();
        } catch (IdentityGovernanceException e) {
            throw new EmailOtpAuthenticatorServerException(
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG.getCode(),
                    AuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_CONFIG.getMessage(), e);
        }
    }

    /**
     * Get email OTP login page URL.
     *
     * @param context AuthenticationContext.
     * @return URL of the OTP login page.
     * @throws AuthenticationFailedException If an error occurred while getting the login page url.
     */
    public static String getEmailOTPLoginPageUrl(AuthenticationContext context) throws AuthenticationFailedException {

        try {
            if (context.getProperty(EMAIL_OTP_AUTHENTICATION_ENDPOINT_URL) != null && StringUtils.isNotBlank(
                    String.valueOf(context.getProperty(EMAIL_OTP_AUTHENTICATION_ENDPOINT_URL)))) {
                return buildURL(String.valueOf(
                        context.getProperty(EMAIL_OTP_AUTHENTICATION_ENDPOINT_URL)), EMAIL_OTP_PAGE);
            }
            return ServiceURLBuilder.create().addPath(EMAIL_OTP_PAGE).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building email OTP login page URL", e);
        }
    }

    /**
     * Get email OTP error page URL.
     *
     * @param context AuthenticationContext.
     * @return URL of the OTP error page.
     * @throws AuthenticationFailedException If an error occurred while getting the error page url.
     */
    public static String getEmailOTPErrorPageUrl(AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            if (context.getProperty(EMAIL_OTP_AUTHENTICATION_ERROR_PAGE_URL) != null && StringUtils.isNotBlank(
                    String.valueOf(context.getProperty(EMAIL_OTP_AUTHENTICATION_ERROR_PAGE_URL)))) {
                return buildURL(String.valueOf(
                        context.getProperty(EMAIL_OTP_AUTHENTICATION_ERROR_PAGE_URL)), ERROR_PAGE);
            }
            return ServiceURLBuilder.create().addPath(ERROR_PAGE).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new AuthenticationFailedException("Error building email OTP error page URL", e);
        }
    }

    /**
     * Get the multi option URI query params.
     *
     * @param request HttpServletRequest.
     */
    @SuppressFBWarnings("SERVLET_PARAMETER")
    public static String getMultiOptionURIQueryParam(HttpServletRequest request) {

        String multiOptionURI = "";
        if (request != null) {
            multiOptionURI = request.getParameter(MULTI_OPTION_QUERY_PARAM);
            multiOptionURI = multiOptionURI != null ? "&" + MULTI_OPTION_QUERY_PARAM + "=" +
                    Encode.forUriComponent(multiOptionURI) : "";
        }
        return multiOptionURI;
    }

    private static String buildURL(String urlFromConfig, String defaultContext) throws URLBuilderException {

        String contextToBuildURL = defaultContext;
        if (StringUtils.isNotBlank(urlFromConfig)) {
            contextToBuildURL = urlFromConfig;
        }
        try {
            if (isURLRelative(contextToBuildURL)) {
                // When tenant qualified URL feature is enabled, this will generate a tenant qualified URL.
                return ServiceURLBuilder.create().addPath(contextToBuildURL).build().getAbsolutePublicURL();
            }
        } catch (URISyntaxException e) {
            throw new URLBuilderException("Error while building public absolute URL for context: " + defaultContext, e);
        }
        // URL from the configuration was an absolute one. We return the same without any modification.
        return contextToBuildURL;
    }

    /**
     * Get Account Lock Connector Configs.
     *
     * @param tenantDomain Tenant domain.
     * @return AccountLockConnectorConfigs Account Lock Connector Configs.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    public static Property[] getAccountLockConnectorConfigs(String tenantDomain) throws
            AuthenticationFailedException {

        Property[] connectorConfigs;
        try {
            connectorConfigs = AuthenticatorDataHolder
                    .getIdentityGovernanceService()
                    .getConfiguration(
                            new String[]{
                                    LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY,
                                    AuthenticatorConstants.PROPERTY_ACCOUNT_LOCK_ON_FAILURE,
                                    FAILED_LOGIN_ATTEMPTS_PROPERTY,
                                    ACCOUNT_UNLOCK_TIME_PROPERTY
                            }, tenantDomain);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error occurred while retrieving account lock connector " +
                    "configuration for tenant : " +  tenantDomain, e);
        }
        return connectorConfigs;
    }

    private static boolean isURLRelative(String contextFromConfig) throws URISyntaxException {

        return !new URI(contextFromConfig).isAbsolute();
    }
}
