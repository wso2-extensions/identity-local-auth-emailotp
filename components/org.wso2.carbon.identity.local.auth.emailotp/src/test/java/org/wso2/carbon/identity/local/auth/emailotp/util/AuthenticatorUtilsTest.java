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
import static org.mockito.Mockito.times;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for {@link AuthenticatorUtils} – runtime param helper methods and triggerDiagnosticLog.
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

    /**
     * Provides scenarios for {@link AuthenticatorUtils#getStringRuntimeParamByName} that should return empty.
     * Format: { runtimeParams, paramName }
     */
    @DataProvider(name = "stringParamEmptyResultProvider")
    public Object[][] stringParamEmptyResultProvider() {

        Map<String, String> otherKey = new HashMap<>();
        otherKey.put("otherParam", "someValue");

        return new Object[][]{
                {null, PARAM_NAME},
                {new HashMap<>(), PARAM_NAME},
                {otherKey, PARAM_NAME},
        };
    }

    @Test(dataProvider = "stringParamEmptyResultProvider",
            description = "Returns empty Optional when the param is absent or map is null/empty.")
    public void testGetStringRuntimeParamByNameReturnsEmpty(Map<String, String> params, String paramName) {

        Optional<String> result = AuthenticatorUtils.getStringRuntimeParamByName(params, paramName);
        assertFalse(result.isPresent(), "Expected empty Optional but got a value.");
    }

    /**
     * Provides scenarios for {@link AuthenticatorUtils#getStringRuntimeParamByName} that should return a value.
     * Format: { runtimeParams, paramName, expectedValue }
     */
    @DataProvider(name = "stringParamPresentProvider")
    public Object[][] stringParamPresentProvider() {

        Map<String, String> single = new HashMap<>();
        single.put(PARAM_NAME, "hello");

        Map<String, String> multiple = new HashMap<>();
        multiple.put(PARAM_NAME, "world");
        multiple.put("other", "ignored");

        return new Object[][]{
                {single, PARAM_NAME, "hello"},
                {multiple, PARAM_NAME, "world"},
        };
    }

    @Test(dataProvider = "stringParamPresentProvider",
            description = "Returns the correct value wrapped in Optional when the key is present.")
    public void testGetStringRuntimeParamByNameReturnsValue(Map<String, String> params, String paramName,
                                                            String expected) {

        Optional<String> result = AuthenticatorUtils.getStringRuntimeParamByName(params, paramName);
        assertTrue(result.isPresent(), "Expected a non-empty Optional.");
        assertEquals(result.get(), expected, "Returned value should match the map entry.");
    }

    /**
     * Provides scenarios for {@link AuthenticatorUtils#getBooleanRuntimeParamByName} that should return empty.
     * Format: { runtimeParams, paramName }
     */
    @DataProvider(name = "booleanParamEmptyResultProvider")
    public Object[][] booleanParamEmptyResultProvider() {

        Map<String, String> otherKey = new HashMap<>();
        otherKey.put("otherParam", "true");

        return new Object[][]{
                {null, PARAM_NAME},
                {new HashMap<>(), PARAM_NAME},
                {otherKey, PARAM_NAME},
        };
    }

    @Test(dataProvider = "booleanParamEmptyResultProvider",
            description = "Returns empty Optional<Boolean> when the param is absent or map is null/empty.")
    public void testGetBooleanRuntimeParamByNameReturnsEmpty(Map<String, String> params, String paramName) {

        Optional<Boolean> result = AuthenticatorUtils.getBooleanRuntimeParamByName(params, paramName);
        assertFalse(result.isPresent(), "Expected empty Optional but got a value.");
    }

    /**
     * Provides scenarios for {@link AuthenticatorUtils#getBooleanRuntimeParamByName} that should return a value.
     * Format: { rawValue, expectedBoolean }
     */
    @DataProvider(name = "booleanParamPresentProvider")
    public Object[][] booleanParamPresentProvider() {

        return new Object[][]{
                {"true", Boolean.TRUE},
                {"false", Boolean.FALSE},
                {"TRUE", Boolean.TRUE},
                {"FALSE", Boolean.FALSE},
                {"invalid", Boolean.FALSE},
        };
    }

    @Test(dataProvider = "booleanParamPresentProvider",
            description = "Returns the correctly parsed Boolean value when the key is present.")
    public void testGetBooleanRuntimeParamByNameReturnsValue(String rawValue, Boolean expected) {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, rawValue);
        Optional<Boolean> result = AuthenticatorUtils.getBooleanRuntimeParamByName(params, PARAM_NAME);
        assertTrue(result.isPresent(), "Expected a non-empty Optional.");
        assertEquals(result.get(), expected, "Parsed boolean should match the expected value.");
    }

    /**
     * Provides scenarios for {@link AuthenticatorUtils#getIntRuntimeParamByName} that should return empty
     * without triggering a diagnostic log.
     * Format: { runtimeParams, paramName }
     */
    @DataProvider(name = "intParamEmptyResultProvider")
    public Object[][] intParamEmptyResultProvider() {

        Map<String, String> otherKey = new HashMap<>();
        otherKey.put("otherParam", "42");

        return new Object[][]{
                {null, PARAM_NAME},
                {new HashMap<>(), PARAM_NAME},
                {otherKey, PARAM_NAME},
        };
    }

    @Test(dataProvider = "intParamEmptyResultProvider",
            description = "Returns empty OptionalInt when the param is absent or map is null/empty.")
    public void testGetIntRuntimeParamByNameReturnsEmpty(Map<String, String> params, String paramName) {

        OptionalInt result = AuthenticatorUtils.getIntRuntimeParamByName(params, paramName);
        assertFalse(result.isPresent(), "Expected empty OptionalInt but got a value.");
    }

    /**
     * Provides scenarios for {@link AuthenticatorUtils#getIntRuntimeParamByName} that should parse successfully.
     * Format: { rawValue, expectedInt }
     */
    @DataProvider(name = "intParamValidProvider")
    public Object[][] intParamValidProvider() {

        return new Object[][]{
                {"0", 0},
                {"5", 5},
                {"-1", -1},
                {"2147483647", Integer.MAX_VALUE},
        };
    }

    @Test(dataProvider = "intParamValidProvider",
            description = "Returns the correctly parsed int value when the key holds a valid integer.")
    public void testGetIntRuntimeParamByNameReturnsValue(String rawValue, int expected) {

        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, rawValue);
        OptionalInt result = AuthenticatorUtils.getIntRuntimeParamByName(params, PARAM_NAME);
        assertTrue(result.isPresent(), "Expected a non-empty OptionalInt.");
        assertEquals(result.getAsInt(), expected, "Parsed integer should match the expected value.");
    }

    /**
     * Provides scenarios for {@link AuthenticatorUtils#getIntRuntimeParamByName} with non-parseable values,
     * paired with whether diagnostic logging is enabled.
     * Format: { rawValue, diagnosticLoggingEnabled, expectedInvocationCount }
     */
    @DataProvider(name = "intParamInvalidProvider")
    public Object[][] intParamInvalidProvider() {

        return new Object[][]{
                {"notAnInt", true, 1},
                {"notAnInt", false, 0},
                {"1.5", true, 1},
                {"1.5", false, 0},
                {"", true, 0},
                {"", false, 0},
        };
    }

    @Test(dataProvider = "intParamInvalidProvider",
            description = "Returns empty OptionalInt for non-parseable values; " +
                    "diagnostic log triggered only when enabled.")
    public void testGetIntRuntimeParamByNameWithInvalidValue(String rawValue, boolean diagnosticEnabled,
                                                             int expectedLogInvocations) {

        mockLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticEnabled);
        Map<String, String> params = new HashMap<>();
        params.put(PARAM_NAME, rawValue);
        OptionalInt result = AuthenticatorUtils.getIntRuntimeParamByName(params, PARAM_NAME);
        assertFalse(result.isPresent(), "Should return empty OptionalInt for a non-parseable value.");
        mockLoggerUtils.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(expectedLogInvocations));
    }

    /**
     * Provides scenarios for {@link AuthenticatorUtils#triggerDiagnosticLog}.
     * Format: { diagnosticLoggingEnabled, resultStatus, expectedInvocationCount }
     */
    @DataProvider(name = "diagnosticLogProvider")
    public Object[][] diagnosticLogProvider() {

        return new Object[][]{
                {true, DiagnosticLog.ResultStatus.SUCCESS, 1},
                {true, DiagnosticLog.ResultStatus.FAILED, 1},
                {false, DiagnosticLog.ResultStatus.SUCCESS, 0},
                {false, DiagnosticLog.ResultStatus.FAILED, 0},
        };
    }

    @Test(dataProvider = "diagnosticLogProvider",
            description = "Triggers DiagnosticLogEvent only when diagnostic logging is enabled.")
    public void testTriggerDiagnosticLog(boolean diagnosticEnabled, DiagnosticLog.ResultStatus status,
                                         int expectedInvocations) {

        mockLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(diagnosticEnabled);
        AuthenticatorUtils.triggerDiagnosticLog(
                "component-id",
                AuthenticatorConstants.LogConstants.ActionIDs.GET_OPTIONAL_INTEGER_RUNTIME_PARAMS,
                "test message",
                status,
                DiagnosticLog.LogDetailLevel.APPLICATION
        );
        mockLoggerUtils.verify(() -> LoggerUtils.triggerDiagnosticLogEvent(any()), times(expectedInvocations));
    }
}

