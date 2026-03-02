/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.local.auth.emailotp.util;

import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.local.auth.emailotp.constant.AuthenticatorConstants;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for {@link AuthenticatorUtils} - runtime param helper methods and logDiagnostic.
 */
public class AuthenticatorUtilsTest {

    private MockedStatic<LoggerUtils> mockLoggerUtils;

    private static final String PARAM_NAME = "testParam";

    @BeforeMethod
    public void setUp() {

        mockLoggerUtils = mockStatic(LoggerUtils.class);
    }

    @AfterMethod
    public void tearDown() {

        mockLoggerUtils.close();
    }

    @Test(description = "Returns empty Optional when runtimeParams map is null.")
    public void testGetOptionalParamFromRuntimeParams_NullMap() {

        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(null, PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty Optional for null map.");
    }

    @Test(description = "Returns empty Optional when runtimeParams map is empty.")
    public void testGetOptionalParamFromRuntimeParams_EmptyMap() {

        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(new HashMap<>(), PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty Optional for empty map.");
    }

    @Test(description = "Returns empty Optional when the key is not present in the map.")
    public void testGetOptionalParamFromRuntimeParams_KeyNotPresent() {

        Map<String, String> params = new HashMap<>();
        params.put("otherParam", "someValue");
        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(params, PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty Optional when key is absent.");
    }

    @Test(description = "Returns the value wrapped in Optional when the key is present.")
    public void testGetOptionalParamFromRuntimeParams_KeyPresent() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "hello");
        Optional<String> result = AuthenticatorUtils.getOptionalParamFromRuntimeParams(params, PARAM_NAME);
        assertTrue(result.isPresent(), "Should return a non-empty Optional when key exists.");
        assertEquals(result.get(), "hello", "Should return the correct value.");
    }

    @Test(description = "Returns empty Optional<Boolean> when runtimeParams map is null.")
    public void testGetOptionalBooleanParamFromRuntimeParams_NullMap() {

        Optional<Boolean> result = AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(null, PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty Optional for null map.");
    }

    @Test(description = "Returns empty Optional<Boolean> when runtimeParams map is empty.")
    public void testGetOptionalBooleanParamFromRuntimeParams_EmptyMap() {

        Optional<Boolean> result =
                AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(new HashMap<>(), PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty Optional for empty map.");
    }

    @Test(description = "Returns empty Optional<Boolean> when key is absent.")
    public void testGetOptionalBooleanParamFromRuntimeParams_KeyNotPresent() {

        Map<String, String> params = new HashMap<>();
        params.put("otherParam", "true");
        Optional<Boolean> result = AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(params, PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty Optional when key is absent.");
    }

    @DataProvider(name = "booleanParamProvider")
    public Object[][] booleanParamProvider() {

        return new Object[][]{
                {"true", Boolean.TRUE},
                {"false", Boolean.FALSE},
                {"TRUE", Boolean.TRUE},
                {"FALSE", Boolean.FALSE},
                {"invalid", Boolean.FALSE},
        };
    }

    @Test(dataProvider = "booleanParamProvider",
            description = "Returns the correctly parsed Boolean value when key is present.")
    public void testGetOptionalBooleanParamFromRuntimeParams_KeyPresent(String rawValue, Boolean expected) {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, rawValue);
        Optional<Boolean> result = AuthenticatorUtils.getOptionalBooleanParamFromRuntimeParams(params, PARAM_NAME);
        assertTrue(result.isPresent(), "Should return a non-empty Optional.");
        assertEquals(result.get(), expected, "Parsed boolean value should match.");
    }

    @Test(description = "Returns empty OptionalInt when runtimeParams map is null.")
    public void testGetOptionalIntParamFromRuntimeParams_NullMap() {

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(null, PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty OptionalInt for null map.");
    }

    @Test(description = "Returns empty OptionalInt when runtimeParams map is empty.")
    public void testGetOptionalIntParamFromRuntimeParams_EmptyMap() {

        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(new HashMap<>(), PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty OptionalInt for empty map.");
    }

    @Test(description = "Returns empty OptionalInt when key is absent.")
    public void testGetOptionalIntParamFromRuntimeParams_KeyNotPresent() {

        Map<String, String> params = new HashMap<>();
        params.put("otherParam", "42");
        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty OptionalInt when key is absent.");
    }

    @Test(description = "Returns the correctly parsed int value when key holds a valid integer.")
    public void testGetOptionalIntParamFromRuntimeParams_ValidInt() {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "5");
        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);
        assertTrue(result.isPresent(), "Should return a non-empty OptionalInt.");
        assertEquals(result.getAsInt(), 5, "Parsed integer value should match.");
    }

    @Test(description = "Returns empty OptionalInt and logs a diagnostic when the value is not a valid integer " +
            "and diagnostic logging is enabled.")
    public void testGetOptionalIntParamFromRuntimeParams_InvalidInt_DiagnosticEnabled() {

        mockLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "notAnInt");
        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty OptionalInt for non-parseable value.");
        // Verify that a diagnostic log was triggered.
        mockLoggerUtils.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(1));
    }

    @Test(description = "Returns empty OptionalInt and skips diagnostic logging when diagnostic logging is disabled.")
    public void testGetOptionalIntParamFromRuntimeParams_InvalidInt_DiagnosticDisabled() {

        mockLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, "notAnInt");
        OptionalInt result = AuthenticatorUtils.getOptionalIntParamFromRuntimeParams(params, PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty OptionalInt for non-parseable value.");
        // Diagnostic event must NOT be triggered.
        mockLoggerUtils.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), never());
    }


    @Test(description = "Triggers a DiagnosticLogEvent when diagnostic logging is enabled.")
    public void testLogDiagnostic_DiagnosticLoggingEnabled() {

        mockLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        AuthenticatorUtils.logDiagnostic(
                "component-id",
                AuthenticatorConstants.LogConstants.ActionIDs.GET_OPTIONAL_INTEGER_RUNTIME_PARAMS,
                "test message",
                DiagnosticLog.ResultStatus.SUCCESS,
                DiagnosticLog.LogDetailLevel.APPLICATION
        );
        mockLoggerUtils.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(1));
    }

    @Test(description = "Does NOT trigger a DiagnosticLogEvent when diagnostic logging is disabled.")
    public void testLogDiagnostic_DiagnosticLoggingDisabled() {

        mockLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        AuthenticatorUtils.logDiagnostic(
                "component-id",
                AuthenticatorConstants.LogConstants.ActionIDs.GET_OPTIONAL_INTEGER_RUNTIME_PARAMS,
                "test message",
                DiagnosticLog.ResultStatus.FAILED,
                DiagnosticLog.LogDetailLevel.APPLICATION
        );
        mockLoggerUtils.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), never());
    }
}

