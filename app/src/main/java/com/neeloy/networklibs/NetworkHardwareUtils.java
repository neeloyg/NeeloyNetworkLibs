package com.neeloy.networklibs;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.hardware.fingerprint.FingerprintManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import static android.content.Context.FINGERPRINT_SERVICE;
import static android.content.Context.KEYGUARD_SERVICE;

/**
 * Created by NeeloyG on 02-05-2017.
 */

public class NetworkHardwareUtils {

    private static  KeyStore keyStore;
    // Variable used for storing the key in the Android Keystore container
    private static final String KEY_NAME = "neeloy_key";
    private static Cipher cipher;

    /**
     * @param context
     * @return {@link Boolean}
     */
    public static boolean isNetworkAvailable(Context context) {
        boolean outcome = false;

        if (context != null) {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

            NetworkInfo[] networkInfos = cm.getAllNetworkInfo();

            for (NetworkInfo tempNetworkInfo : networkInfos) {

                /**
                 * Can also check if the user is in roaming
                 */
                if (tempNetworkInfo != null && tempNetworkInfo.isConnected()) {
                    outcome = true;
                    break;
                }
            }
        }

        return outcome;
    }

    /**
     * @param context
     * @return {@link String}
     */
    public static String getDeviceId(Context context) {
        TelephonyManager telephonyManager = (TelephonyManager) context
                .getSystemService(Context.TELEPHONY_SERVICE);
        return telephonyManager.getDeviceId();
    }

    /**
     * @param context
     */
    public static void hideKeyBoard(Context context) {
        InputMethodManager inputManager = (InputMethodManager)
                context.getSystemService(Context.INPUT_METHOD_SERVICE);

        inputManager.hideSoftInputFromWindow(((Activity) context).getCurrentFocus().getWindowToken(),
                InputMethodManager.HIDE_NOT_ALWAYS);

    }

    /**
     * @param context
     * @return {@link ArrayList<SimInfo>}
     */
    public static ArrayList<SimInfo> getDualSIMinfo(Context context) {
        ArrayList<SimInfo> SIM_LIST = new ArrayList<SimInfo>();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            SubscriptionManager mSubscriptionManager = SubscriptionManager.from(context);
            List<SubscriptionInfo> subInfoList = mSubscriptionManager.getActiveSubscriptionInfoList();
            for (SubscriptionInfo subscriptionInfo : subInfoList) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    SimInfo simInfo = new SimInfo();
                    simInfo.setDisplay_name(subscriptionInfo.getDisplayName().toString());
                    simInfo.setSubscription_id("" + subscriptionInfo.getSubscriptionId());
                    SIM_LIST.add(simInfo);
                }
            }
        }
        return SIM_LIST;
    }

    /**
     * @param email
     * @return {@link Boolean}
     */
    public static boolean emailValidator(String email) {
        Pattern pattern;
        Matcher matcher;
        // final String EMAIL_PATTERN = "^[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
        final String EMAIL_PATTERN = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)\\])";
        pattern = Pattern.compile(EMAIL_PATTERN);
        matcher = pattern.matcher(email);
        boolean status = matcher.matches();
        System.out.println("Email validation status: " + status);
        return status;
    }

    /**
     * @param panNo
     * @return {@link Boolean}
     */
    public static boolean panValidator(String panNo) {
        Pattern pattern;
        Matcher matcher;
        final String PAN_PATTERN = "[A-Z|a-z]{5}[0-9]{4}[A-Z|a-z]{1}";
        //final String PAN_PATTERN = "[A-Z]{5}[0-9]{4}[A-Z]{1}";
        pattern = Pattern.compile(PAN_PATTERN);
        matcher = pattern.matcher(panNo);
        boolean status = matcher.matches();
        System.out.println("PAN validation status: " + status);
        return status;
    }

    /**
     * @param ifsc
     * @return {@link Boolean}
     */
    public static boolean ifscValidator(String ifsc) {
        Pattern pattern;
        Matcher matcher;
        final String IFSC_PATTERN = "[A-Z|a-z]{4}[0][\\d]{6}$";
        pattern = Pattern.compile(IFSC_PATTERN);
        matcher = pattern.matcher(ifsc);
        boolean status = matcher.matches();
        System.out.println("IFSC validation status: " + status);
        return status;
    }

    /**
     * @param value
     * @return {@link Boolean}
     */
    public static boolean InvalidCharValidator(String value) {
        Pattern pattern;
        Matcher matcher;
        final String userID_pattern = "^[a-zA-Z0-9._-]+$";
        pattern = Pattern.compile(userID_pattern);
        matcher = pattern.matcher(value);
        boolean status = matcher.matches();
        System.out.println("Character validation status: " + status);
        return status;
    }

    /**
     * @param language,context
     */

    public static void setApplicationLanguage(Language language, Activity context) {
        Locale locale = new Locale(language.name());
        Locale.setDefault(locale);
        Configuration config = new Configuration();
        config.locale = locale;
        context.getResources().updateConfiguration(config,
                context.getResources().getDisplayMetrics());
    }

    /**
     * Determines the difference between two dates
     *
     * @param date1
     * @param date2
     * @return difference in days in long
     */
    public static long getDifferenceInDays(Date date1, Date date2) {
        if (date1 == null || date2 == null) {
            throw new IllegalArgumentException("Both dates are mandatory");
        }
        long diff = Math.abs(date1.getTime() - date2.getTime());
        long diffDays = diff / (24 * 60 * 60 * 1000);

        return diffDays;
    }

    /**
     * Checks if the device is rooted.
     *
     * @return <code>true</code> if the device is rooted, <code>false</code> otherwise.
     */
    public static boolean isRooted() {
        // get from build info
        String buildTags = android.os.Build.TAGS;
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true;
        }
        // check if /system/app/Superuser.apk is present
        try {
            File file = new File("/system/app/Superuser.apk");
            if (file.exists()) {
                return true;
            }
        } catch (Exception e1) {
            // ignore
        }

        // try executing commands
        return canExecuteCommand("/system/xbin/which su")
                || canExecuteCommand("/system/bin/which su") || canExecuteCommand("which su");
    }

    // executes a command on the system
    private static boolean canExecuteCommand(String command) {
        boolean executedSuccesfully;
        try {
            Runtime.getRuntime().exec(command);
            executedSuccesfully = true;
        } catch (Exception e) {
            executedSuccesfully = false;
        }

        return executedSuccesfully;
    }

    /**
     * Determines whether is mobile number or not
     *
     * @param text
     * @return boolean
     */
    public static boolean isMobileNumber(String text) {
        if (text.matches("(^[7-9][0-9]{9}$)"))
            return true;
        else
            return false;
    }

    public static void validateFingerPrintDetection(Context context, FingerprintHandler.IFingerprintListener iFingerprintListener){
        // Initializing both Android Keyguard Manager and Fingerprint Manager
        KeyguardManager keyguardManager = (KeyguardManager) context.getSystemService(KEYGUARD_SERVICE);
        FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(FINGERPRINT_SERVICE);
        // Check whether the device has a Fingerprint sensor.
        if(!fingerprintManager.isHardwareDetected()){
            /**
             * An error message will be displayed if the device does not contain the fingerprint hardware.
             * However if you plan to implement a default authentication method,
             * you can redirect the user to a default authentication activity from here.
             * Example:
             * Intent intent = new Intent(this, DefaultAuthenticationActivity.class);
             * startActivity(intent);
             */
            Toast.makeText(context,"Your Device does not have a Fingerprint Sensor",Toast.LENGTH_SHORT).show();
        }else {
            // Checks whether fingerprint permission is set on manifest
            if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(context,"Fingerprint authentication permission not enabled",Toast.LENGTH_SHORT).show();
            }else{
                // Check whether at least one fingerprint is registered
                if (!fingerprintManager.hasEnrolledFingerprints()) {
                    Toast.makeText(context,"Register at least one fingerprint in Settings",Toast.LENGTH_SHORT).show();
                }else{
                    // Checks whether lock screen security is enabled or not
                    if (!keyguardManager.isKeyguardSecure()) {
                        Toast.makeText(context,"Lock screen security not enabled in Settings",Toast.LENGTH_SHORT).show();
                    }else{
                        generateKey();
                        if (cipherInit()) {
                            FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
                            FingerprintHandler helper = new FingerprintHandler(context,iFingerprintListener);
                            helper.startAuth(fingerprintManager, cryptoObject);
                        }
                    }
                }
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private static  void generateKey() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (Exception e) {
            e.printStackTrace();
        }

        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to get KeyGenerator instance", e);
        }

        try {
            keyStore.load(null);
            keyGenerator.init(new
                    KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException |
                InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private static boolean cipherInit() {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,
                    null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }
}
