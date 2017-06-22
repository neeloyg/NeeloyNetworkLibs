package com.neeloy.networklibs;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Created by NeeloyG on 03-05-2017.
 */

public class JsonUtils {

    /**
     * @param jsObj
     * @param key
     * @return {@link String}
     */
    public static String getvalueFromJson(JSONObject jsObj, String key) {
        String value = "";

        if (jsObj != null) {

            if (key != null) {
                try {
                    if (jsObj.has(key)) {
                        if (jsObj.getString(key) != null && jsObj.getString(key).length() > 0 && !jsObj.getString(key).equalsIgnoreCase("null"))
                            value = jsObj.getString(key);
                    }
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            } else {
                try {
                    throw new JSONException("Json key is null");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        } else {
            try {
                throw new JSONException("Json Object is null");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return value;
    }
}
