package com.neeloy.networklibs;

import android.os.AsyncTask;
import android.util.Log;

import java.io.InputStream;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.HttpsURLConnection;

/**
 * Created by NeeloyG on 03-05-2017.
 */

public class SSLPinningHTTPSServer {

    private static boolean final_result = false;

    /**
     * @param hostName          of domain
     * @param inputStreamRawKey {@link InputStream of certificate kept in raw folder}
     * @return {@link Boolean}
     */
    public static void getSSLPinningStatus(String hostName, InputStream inputStreamRawKey, final IsslPinListener isslPinListener) {
        new SSLChecking(new SSLChecking.ICompletionListener() {
            @Override
            public void getResult(boolean result) {
                final_result = result;
                isslPinListener.getStatus(result);
            }
        }, hostName, inputStreamRawKey).execute();

    }

    private static boolean checkSSLPin(String hostName, InputStream inputStreamRawKey) {

        PublicKey keyRemote = null;
        PublicKey keyLocal = null;

        if (hostName.contains("http://")) {
            Log.d("ssltype", "http");
            return true;
        } else {
            try {
                URL destinationURL = new URL(hostName);
                HttpsURLConnection conn = (HttpsURLConnection) destinationURL
                        .openConnection();
                conn.connect();
                Certificate[] certs = conn.getServerCertificates();
                Certificate cert = certs[0];
                keyRemote = cert.getPublicKey();
            } catch (Exception e) {
                e.printStackTrace();


            }

            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate ca;
                try {
                    ca = cf.generateCertificate(inputStreamRawKey);
                    keyLocal = ca.getPublicKey();
                } finally {
                    inputStreamRawKey.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            //Matching both keys
            if (keyLocal.equals(keyRemote)) {
                return true;
            } else {
                return false;
            }

        }


    }


    private static class SSLChecking extends AsyncTask<Void, Void, Void> {

        private ICompletionListener iCompletionListener;
        private String hostName = "";
        private InputStream inputStreamRawKey;

        public SSLChecking(ICompletionListener iCompletionListener, String hostName, InputStream inputStreamRawKey) {
            this.iCompletionListener = iCompletionListener;
            this.hostName = hostName;
            this.inputStreamRawKey = inputStreamRawKey;
        }

        @Override
        protected Void doInBackground(Void... params) {
            if (checkSSLPin(hostName, inputStreamRawKey)) {
                final_result = true;
            } else {
                final_result = false;
            }
            return null;
        }


        @Override
        protected void onPostExecute(Void aVoid) {
            super.onPostExecute(aVoid);
            if (final_result) {
                iCompletionListener.getResult(true);
            } else {
                iCompletionListener.getResult(false);
            }
        }

        private interface ICompletionListener {

            public void getResult(boolean result);

        }


    }
}
