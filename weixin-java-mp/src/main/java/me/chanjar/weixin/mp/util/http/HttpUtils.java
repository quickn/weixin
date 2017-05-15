package me.chanjar.weixin.mp.util.http;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Created by pc on 2017/2/24.
 */
public class HttpUtils {
    private static final String USER_AGENT = "Mozilla/5.0";
    private static Logger logger = LoggerFactory.getLogger("HttpUtils");

    private static final String GET_URL = "http://localhost:9090/SpringMVCExample";

    private static final String POST_URL = "http://localhost:9090/SpringMVCExample/home";

    public static void main(String[] args) throws IOException {

    }

    public static JsonElement GET(String GET_URL) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(GET_URL);
        httpGet.addHeader("User-Agent", USER_AGENT);
        CloseableHttpResponse httpResponse = httpClient.execute(httpGet);
        System.out.println("GET Response Status:: "
                + httpResponse.getStatusLine().getStatusCode());
        BufferedReader reader = new BufferedReader(new InputStreamReader(
                httpResponse.getEntity().getContent()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = reader.readLine()) != null) {
            response.append(inputLine);
        }
        reader.close();
        // print result
        System.out.println(response.toString());
        httpClient.close();
        return new JsonParser().parse(response.toString());
    }

    public static JsonObject POST(String url, String paras) {
        CloseableHttpClient httpclient = null;
        CloseableHttpResponse httpresponse = null;
        try {
            HttpPost httppost = new HttpPost(url);
            httppost.addHeader("Content-Type", "application/json");
            StringEntity se = new StringEntity(paras, "UTF-8");
            se.setContentType("text/json");
            se.setContentEncoding(new BasicHeader(HTTP.CONTENT_TYPE, "application/json"));
            httppost.setEntity(se);
            httpclient = HttpClients.custom().build();//HttpClients.custom().setSSLSocketFactory(createSSLConnSocketFactory()).setConnectionManager(connMgr).setDefaultRequestConfig(requestConfig).build();
            httpresponse = httpclient.execute(httppost);
            int statusCode = httpresponse.getStatusLine().getStatusCode();
            String resultInfo = EntityUtils.toString(httpresponse.getEntity(), "UTF-8");
            logger.info("POST statusCode=" + statusCode + ", resultInfo=" + resultInfo);
            if (200 == statusCode) {
                return new JsonParser().parse(resultInfo).getAsJsonObject();
            }
        } catch (Exception e) {
            logger.error("WeixinHelper.Notice.Exception1", e);
        } finally {
            try {
                if (httpresponse != null) {
                    httpresponse.close();
                }
                if (httpclient != null) {
                    httpclient.close();
                }
            } catch (Exception e) {
                logger.error("POST.Exception2", e);
            }
        }
        return null;
    }
}
