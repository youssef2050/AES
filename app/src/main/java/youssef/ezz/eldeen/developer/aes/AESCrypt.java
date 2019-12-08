package youssef.ezz.eldeen.developer.aes;


import android.os.Build;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class AESCrypt {

    private static final String TAG = "AESCrypt";

    private static final String AES_MODE = "AES/CBC/PKCS7Padding";
    private static final String CHARSET = "UTF-8";

    private static final String HASH_ALGORITHM = "SHA-256";
    private static final byte[] ivBytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    private static boolean DEBUG_LOG_ENABLED = true;

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private static SecretKeySpec generateKey(final String password) throws NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
        byte[] bytes = password.getBytes(StandardCharsets.UTF_8);
        digest.update(bytes, 0, bytes.length);
        byte[] key = digest.digest();
        return new SecretKeySpec(key, "AES");
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    static String encrypt(final String password, String message)
            throws GeneralSecurityException {

        try {
            final SecretKeySpec key = generateKey(password);
            byte[] cipherText = encrypt(key, message.getBytes(CHARSET));
            System.out.println(Base64.encodeToString(cipherText, Base64.NO_WRAP));
            return Base64.encodeToString(cipherText, Base64.NO_WRAP);
        } catch (UnsupportedEncodingException e) {
            if (DEBUG_LOG_ENABLED)
                Log.e(TAG, "UnsupportedEncodingException ", e);
            throw new GeneralSecurityException(e);
        }
    }

    private static byte[] encrypt(final SecretKeySpec key, final byte[] message)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(AES_MODE);
        IvParameterSpec ivSpec = new IvParameterSpec(AESCrypt.ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(message);
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    static String decrypt(final String password, String base64EncodedCipherText)
            throws GeneralSecurityException {

        try {
            final SecretKeySpec key = generateKey(password);
            byte[] decodedCipherText = Base64.decode(base64EncodedCipherText, Base64.NO_WRAP);
            byte[] decryptedBytes = decrypt(key, decodedCipherText);
            return new String(decryptedBytes, CHARSET);
        } catch (UnsupportedEncodingException e) {
            if (DEBUG_LOG_ENABLED)
                Log.e(TAG, "UnsupportedEncodingException ", e);
            throw new GeneralSecurityException(e);
        }
    }

    private static byte[] decrypt(final SecretKeySpec key, final byte[] decodedCipherText)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(AES_MODE);
        IvParameterSpec ivSpec = new IvParameterSpec(AESCrypt.ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(decodedCipherText);
    }

//    private static String bytesToHex(byte[] bytes) {
//        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
//                '9', 'A', 'B', 'C', 'D', 'E', 'F'};
//        char[] hexChars = new char[bytes.length * 2];
//        int v;
//        for (int j = 0; j < bytes.length; j++) {
//            v = bytes[j] & 0xFF;
//            hexChars[j * 2] = hexArray[v >>> 4];
//            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
//        }
//        return new String(hexChars);
//    }

    private AESCrypt() {
    }
}

