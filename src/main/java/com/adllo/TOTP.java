package com.adllo;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class TOTP {

    /**
     * Paso de tiempo predeterminado que es parte de la especificación, 30 segundos es el valor predeterminado
     */
    public static final int DEFAULT_TIME_STEP_SECONDS = 30;
    /**
     * Número predeterminado de dígitos en una cadena OTP
     */
    public static int DEFAULT_OTP_LENGTH = 6;
    /**
     * Alto y ancho predeterminado de la imagen QR
     */
    public static int DEFAULT_QR_DIMENTION = 200;
    /**
     * Establezca el número de dígitos para controlar el prefijo 0, establezca en 0 si no hay prefijo
     */
    private static int MAX_NUM_DIGITS_OUTPUT = 100;

    private static final String blockOfZeros;

    static {
        char[] chars = new char[MAX_NUM_DIGITS_OUTPUT];
        Arrays.fill(chars, '0');
        blockOfZeros = new String(chars);
    }

    /**
     * Genere y devuelva una clave secreta de 16 caracteres en formato base32 (A-Z2-7) usando {@link SecureRandom}. Puede ser usado
     * para generar la imagen QR que se compartirá con el usuario. Si desea utilizar otras longitudes usar {@link #generateBase32Secret(int)}.
     */
    public static String generateBase32Secret() {
        return generateBase32Secret(16);
    }

    /**
     * Similar a {@link #generateBase32Secret()} pero especificando la longitud.
     */
    public static String generateBase32Secret(int numDigits) {
        StringBuilder sb = new StringBuilder(numDigits);
        Random random = new SecureRandom();
        for (int i = 0; i < numDigits; i++) {
            int val = random.nextInt(32);
            if (val < 26) {
                sb.append((char) ('A' + val));
            } else {
                sb.append((char) ('2' + (val - 26)));
            }
        }
        return sb.toString();
    }

    /**
     * Devuelve el número actual que se va a comprobar. Esto se puede comparar con la entrada del usuario.
     *
     * <p>
     * ADVERTENCIA: Esto requiere un reloj del sistema que esté sincronizado con el mundo.
     * </p>
     *
     * @param base32Secret Cadena secreta codificada con base 32 que se utilizó para generar el código QR o se compartió con el usuario.
     * @return Un número como una cadena con posibles ceros a la izquierda que debe coincidir con la salida de la aplicación de autenticación del usuario.
     */
    public static String generateCurrentNumberString(String base32Secret) throws GeneralSecurityException {
        return generateNumberString(base32Secret, System.currentTimeMillis(), DEFAULT_TIME_STEP_SECONDS, DEFAULT_OTP_LENGTH);
    }

    /**
     * Similar a {@link #generateCurrentNumberString(String)} excepto expone otros parámetros. Principalmente para pruebas.
     *
     * @param base32Secret    Cadena secreta codificada con base 32 que se utilizó para generar el código QR o se compartió con el usuario.
     * @param timeMillis      Tiempo en milisegundos.
     * @param timeStepSeconds Paso de tiempo en segundos. El valor predeterminado aquí es 30 segundos. Ver {@link #DEFAULT_TIME_STEP_SECONDS}.
     * @param numDigits       El número de dígitos de la OTP.
     * @return Un número como una cadena con posibles ceros a la izquierda que debe coincidir con la salida de la aplicación de autenticación del usuario.
     */
    public static String generateNumberString(String base32Secret, long timeMillis, int timeStepSeconds, int numDigits) throws GeneralSecurityException {
        int number = generateNumber(base32Secret, timeMillis, timeStepSeconds, numDigits);
        return zeroPrepend(number, numDigits);
    }

    /**
     * Similar a {@link #generateNumberString(String, long, int, int)} pero esto devuelve un int en lugar de una cadena de texto.
     *
     * @return Un número que debe coincidir con el resultado de la aplicación de autenticación del usuario.
     */
    public static int generateNumber(String base32Secret, long timeMillis, int timeStepSeconds, int numDigits) throws GeneralSecurityException {
        long value = timeMillis / 1000 / timeStepSeconds;
        byte[] key = decodeBase32(base32Secret);
        return generateNumberFromKeyValue(key, value, numDigits);
    }

    /**
     * Devuelve la url de la imagen QR gracias a Google. Esto se puede mostrar al usuario y el programa de autenticación
     * puede escanear como una manera fácil de ingresar el secreto.
     *
     * @param keyId  Nombre de la clave que desea que aparezca en la aplicación de autenticación de usuarios. La URL ya debería estar codificada.
     * @param secret Cadena secreta que se utilizará al generar el número actual.
     */
    public static String qrImageUrl(String keyId, String secret) {
        StringBuilder sb = new StringBuilder(128);
        sb.append("https://chart.googleapis.com/chart?chs=")
                .append(DEFAULT_QR_DIMENTION)
                .append("x")
                .append(DEFAULT_QR_DIMENTION)
                .append("&cht=qr&chl=")
                .append(DEFAULT_QR_DIMENTION)
                .append("x")
                .append(DEFAULT_QR_DIMENTION)
                .append("&chld=M|0&cht=qr&chl=");

        sb.append("otpauth://totp/")
                .append(keyId)
                .append("%3Fsecret%3D")
                .append(secret)
                .append("%26digits%3D")
                .append(DEFAULT_OTP_LENGTH);

        return sb.toString();
    }

    private static int generateNumberFromKeyValue(byte[] key, long value, int numDigits) throws GeneralSecurityException {
        byte[] data = new byte[8];
        for (int i = 7; value > 0; i--) {
            data[i] = (byte) (value & 0xFF);
            value >>= 8;
        }

        // Cifra los datos con la clave y devuelve el SHA1 en hexadecimal
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);

        byte[] hash = mac.doFinal(data);

        // Obtener los 4 bits menos significativos de la cadena cifrada como un desplazamiento
        int offset = hash[hash.length - 1] & 0xF;

        // Estamos usando long porque Java no tiene int sin firmar.
        long truncatedHash = 0;
        for (int i = offset; i < offset + 4; ++i) {
            truncatedHash <<= 8;
            // Obtener los 4 bytes en el desplazamiento
            truncatedHash |= (hash[i] & 0xFF);
        }
        // Cortar la parte superior
        truncatedHash &= 0x7FFFFFFF;

        // El token son los últimos dígitos <length> del número
        long mask = 1;
        for (int i = 0; i < numDigits; i++) {
            mask *= 10;
        }
        truncatedHash %= mask;
        return (int) truncatedHash;
    }

    static String zeroPrepend(int num, int digits) {
        String numStr = Integer.toString(num);
        if (numStr.length() >= digits) {
            return numStr;
        } else {
            StringBuilder sb = new StringBuilder(digits);
            int zeroCount = digits - numStr.length();
            sb.append(blockOfZeros, 0, zeroCount);
            sb.append(numStr);
            return sb.toString();
        }
    }

    /**
     * Decodificar cadena base-32. Expuesto para pruebas.
     */
    static byte[] decodeBase32(String str) {
        // Cada carácter en base 32 codifica 5 bits
        int numBytes = ((str.length() * 5) + 7) / 8;
        byte[] result = new byte[numBytes];
        int resultIndex = 0;
        int which = 0;
        int working = 0;
        for (int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            int val;
            if (ch >= 'a' && ch <= 'z') {
                val = ch - 'a';
            } else if (ch >= 'A' && ch <= 'Z') {
                val = ch - 'A';
            } else if (ch >= '2' && ch <= '7') {
                val = 26 + (ch - '2');
            } else if (ch == '=') {
                // special case
                which = 0;
                break;
            } else {
                throw new IllegalArgumentException("Invalid base-32 character: " + ch);
            }

            switch (which) {
                case 0:
                    // Los 5 bits son los 5 bits superiores
                    working = (val & 0x1F) << 3;
                    which = 1;
                    break;
                case 1:
                    // Los 3 bits superiores son los 3 bits inferiores.
                    working |= (val & 0x1C) >> 2;
                    result[resultIndex++] = (byte) working;
                    // lower 2 bits is upper 2 bits
                    working = (val & 0x03) << 6;
                    which = 2;
                    break;
                case 2:
                    // Los 5 bits son mediados de 5 bits
                    working |= (val & 0x1F) << 1;
                    which = 3;
                    break;
                case 3:
                    // El bit superior es el bit más bajo
                    working |= (val & 0x10) >> 4;
                    result[resultIndex++] = (byte) working;
                    // lower 4 bits is top 4 bits
                    working = (val & 0x0F) << 4;
                    which = 4;
                    break;
                case 4:
                    // Los 4 bits superiores son los 4 bits más bajos.
                    working |= (val & 0x1E) >> 1;
                    result[resultIndex++] = (byte) working;
                    // lower 1 bit is top 1 bit
                    working = (val & 0x01) << 7;
                    which = 5;
                    break;
                case 5:
                    // Los 5 bits son mediados de 5 bits
                    working |= (val & 0x1F) << 2;
                    which = 6;
                    break;
                case 6:
                    // Los 2 bits superiores son los 2 bits más bajos.
                    working |= (val & 0x18) >> 3;
                    result[resultIndex++] = (byte) working;
                    // lower 3 bits of byte 6 is top 3 bits
                    working = (val & 0x07) << 5;
                    which = 7;
                    break;
                case 7:
                    // Los 5 bits son 5 bits inferiores
                    working |= (val & 0x1F);
                    result[resultIndex++] = (byte) working;
                    which = 0;
                    break;
            }
        }
        if (which != 0) {
            result[resultIndex++] = (byte) working;
        }
        if (resultIndex != result.length) {
            result = Arrays.copyOf(result, resultIndex);
        }
        return result;
    }

}
