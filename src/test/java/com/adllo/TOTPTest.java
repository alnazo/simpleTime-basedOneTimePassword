package com.adllo;

import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TOTPTest {

    @Test
    public void testZeroPrepend() {
        Random random = new Random();
        for (int i = 0; i < 10000; i++) {
            int num = random.nextInt(1000000);
            assertEquals(String.format("%06d", num), TOTP.zeroPrepend(num, 6));
        }
    }

    @Test
    public void testDecodeBase32() {
        Random random = new Random();
        random.nextBytes(new byte[100]);
        Base32 base32 = new Base32();
        for (int i = 0; i < 10000; i++) {
            byte[] bytes = new byte[random.nextInt(10) + 1];
            random.nextBytes(bytes);
            String encoded = base32.encodeAsString(bytes);
            byte[] expected = base32.decode(encoded);
            byte[] actual = TOTP.decodeBase32(encoded);
            assertArrayEquals(expected, actual);
        }
    }

    @Test
    public void testBadBase32() {
        String[] strings = new String[]{"A", "AB", "ABC", "ABCD", "ABCDE", "ABCDEF", "ABCDEFG", "ABCDEFGH", "ABCDEFGHI"};
        Base32 base32 = new Base32();
        for (String str : strings) {
            byte[] decoded = TOTP.decodeBase32(str);
            String encoded = base32.encodeAsString(decoded);
            byte[] result = TOTP.decodeBase32(encoded);
            assertArrayEquals(decoded, result);
        }
    }

    @Test
    public void testVariusKnownSecretTimeCodes() throws GeneralSecurityException {
        String secret = "NY4A5CPJZ46LXZCP";

        testStringAndNumber(secret, 1000L, 748810, "748810");
        testStringAndNumber(secret, 7451000L, 325893, "325893");
        testStringAndNumber(secret, 15451000L, 64088, "064088");
        testStringAndNumber(secret, 348402049542546145L, 9637, "009637");
        testStringAndNumber(secret, 2049455124374752571L, 743, "000743");
        testStringAndNumber(secret, 1359002349304873750L, 92, "000092");
        testStringAndNumber(secret, 6344447817348357059L, 7, "000007");
        testStringAndNumber(secret, 2125701285964551130L, 0, "000000");

        testStringAndNumber(secret, 7451000L, 3, "3", 1);
        testStringAndNumber(secret, 7451000L, 93, "93", 2);
        testStringAndNumber(secret, 7451000L, 893, "893", 3);
        testStringAndNumber(secret, 7451000L, 5893, "5893", 4);
        testStringAndNumber(secret, 7451000L, 25893, "25893", 5);
        testStringAndNumber(secret, 7451000L, 325893, "325893", 6);
        testStringAndNumber(secret, 7451000L, 9325893, "9325893", 7);
        testStringAndNumber(secret, 7451000L, 89325893, "89325893", 8);

        testStringAndNumber(secret, 1000L, 34748810, "34748810", 8);
        testStringAndNumber(secret, 7451000L, 89325893, "89325893", 8);
        testStringAndNumber(secret, 15451000L, 67064088, "67064088", 8);
        testStringAndNumber(secret, 5964551130L, 5993908, "05993908", 8);
        testStringAndNumber(secret, 348402049542546145L, 26009637, "26009637", 8);
        testStringAndNumber(secret, 2049455124374752571L, 94000743, "94000743", 8);
        testStringAndNumber(secret, 1359002349304873750L, 86000092, "86000092", 8);
        testStringAndNumber(secret, 6344447817348357059L, 80000007, "80000007", 8);
        testStringAndNumber(secret, 2125701285964551130L, 24000000, "24000000", 8);
    }

    private void testStringAndNumber(String secret, long timeMillis, long expectedNumber, String expectedString) throws GeneralSecurityException {
        testStringAndNumber(secret, timeMillis, expectedNumber, expectedString, TOTP.DEFAULT_OTP_LENGTH);
    }

    private void testStringAndNumber(String secret, long timeMillis, long expectedNumber, String expectedString, int length) throws GeneralSecurityException {
        String str = TOTP.generateNumberString(secret, timeMillis, TOTP.DEFAULT_TIME_STEP_SECONDS, length);
        assertEquals(length, str.length());
        assertEquals(expectedString, str);
        assertEquals(expectedNumber, TOTP.generateNumber(secret, timeMillis, TOTP.DEFAULT_TIME_STEP_SECONDS, length), "expected numbers to match");
    }

    @Test
    public void testGenerateSecret() {
        assertEquals(16, TOTP.generateBase32Secret().length());
        assertEquals(16, TOTP.generateBase32Secret(16).length());
        assertEquals(1, TOTP.generateBase32Secret(1).length());
    }
}
