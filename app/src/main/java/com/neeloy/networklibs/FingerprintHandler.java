package com.neeloy.networklibs;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.support.v4.app.ActivityCompat;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Created by whit3hawks on 11/16/16.
 */
public class FingerprintHandler extends FingerprintManager.AuthenticationCallback {

    private Context context;
    private IFingerprintListener mIFingerprintListener;

    // Constructor
    public FingerprintHandler(Context mContext,IFingerprintListener mIFingerprintListener) {
        context = mContext;
        this.mIFingerprintListener=mIFingerprintListener;
    }

    public void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject) {
        CancellationSignal cancellationSignal = new CancellationSignal();
        if (ActivityCompat.checkSelfPermission(context, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        manager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
    }

    @Override
    public void onAuthenticationError(int errMsgId, CharSequence errString) {
        mIFingerprintListener.getAuthentication(false,"Fingerprint Authentication error\n" + errString);
       // Toast.makeText(context,"Fingerprint Authentication error\n" + errString,Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
        Toast.makeText(context,"Fingerprint Authentication help\n" + helpString,Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onAuthenticationFailed() {
        mIFingerprintListener.getAuthentication(false,"Fingerprint Authentication failed.");
        Toast.makeText(context,"Fingerprint Authentication failed.",Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        mIFingerprintListener.getAuthentication(true,"Fingerprint Authentication successfull.");
    }




    public interface IFingerprintListener{

        public void getAuthentication(boolean result,String message);
    }


}
