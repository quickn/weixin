package me.chanjar.weixin.mp.api.impl;

import com.google.gson.*;
import me.chanjar.weixin.common.bean.WxAccessToken;
import me.chanjar.weixin.common.bean.WxJsapiSignature;
import me.chanjar.weixin.common.bean.result.WxError;
import me.chanjar.weixin.common.exception.WxErrorException;
import me.chanjar.weixin.common.session.StandardSessionManager;
import me.chanjar.weixin.common.session.WxSessionManager;
import me.chanjar.weixin.common.util.RandomUtils;
import me.chanjar.weixin.common.util.crypto.SHA1;
import me.chanjar.weixin.common.util.http.*;
import me.chanjar.weixin.mp.api.*;
import me.chanjar.weixin.mp.bean.*;
import me.chanjar.weixin.mp.bean.result.*;
import me.chanjar.weixin.mp.util.http.HttpUtils;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.locks.Lock;

public class WxMpServiceImpl implements WxMpService {

    private static final JsonParser JSON_PARSER = new JsonParser();

    protected final Logger log = LoggerFactory.getLogger(this.getClass());
    protected WxSessionManager sessionManager = new StandardSessionManager();
    private WxMpConfigStorage wxMpConfigStorage;
    private WxMpKefuService kefuService = new WxMpKefuServiceImpl(this);
    private WxMpMaterialService materialService = new WxMpMaterialServiceImpl(this);
    private WxMpMenuService menuService = new WxMpMenuServiceImpl(this);
    private WxMpUserService userService = new WxMpUserServiceImpl(this);
    private WxMpUserTagService tagService = new WxMpUserTagServiceImpl(this);
    private WxMpQrcodeService qrCodeService = new WxMpQrcodeServiceImpl(this);
    private WxMpCardService cardService = new WxMpCardServiceImpl(this);
    private WxMpStoreService storeService = new WxMpStoreServiceImpl(this);
    private WxMpDataCubeService dataCubeService = new WxMpDataCubeServiceImpl(this);
    private WxMpUserBlacklistService blackListService = new WxMpUserBlacklistServiceImpl(this);
    private WxMpTemplateMsgService templateMsgService = new WxMpTemplateMsgServiceImpl(this);
    private WxMpDeviceService deviceService = new WxMpDeviceServiceImpl(this);
    private CloseableHttpClient httpClient;
    private HttpHost httpProxy;
    private int retrySleepMillis = 1000;
    private int maxRetryTimes = 5;

    public static String COMPONENT_VERIFY_TICKET = "component_verify_ticket_%s";
    private static final String COMPONENT_ACCESS_TOKEN = "component_access_token_%s";
    private static final String AUTHORIZER_REFRESH_TOKEN = "authorizer_refauthorizer_access_token_resh_token_%s_%s";
    private static final String AUTHORIZER_ACCESS_TOKEN = "%s_%s";
    private static String AUTH_CODE = "auth_code_%s_%s";

    private CacheService cacheService;

    public CacheService getCacheService() {
        return cacheService;
    }

    public void setCacheService(CacheService cacheService) {
        this.cacheService = cacheService;
    }

    @Override
    public boolean checkSignature(String timestamp, String nonce, String signature) {
        try {
            return SHA1.gen(this.getWxMpConfigStorage().getToken(), timestamp, nonce)
                    .equals(signature);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String getAccessToken(final String... authorizer_appid) throws WxErrorException {
        return getAccessToken(false, authorizer_appid);
    }

    @Override
    public String getAccessToken(boolean forceRefresh, final String... authorizer_appid) throws WxErrorException {
        Lock lock = this.getWxMpConfigStorage().getAccessTokenLock();
        try {
            lock.lock();
            if (forceRefresh) {
                this.getWxMpConfigStorage().expireAccessToken(authorizer_appid);
            }
            if (this.getWxMpConfigStorage().isAccessTokenExpired(authorizer_appid)) {
                if (authorizer_appid.length != 0 && authorizer_appid[0] != null) {
                    authorizerAccessTokenGet(authorizer_appid[0]);
                } else {
                    String url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential" +
                            "&appid=" + this.getWxMpConfigStorage().getAppId() + "&secret="
                            + this.getWxMpConfigStorage().getSecret();
                    WxError result = HttpGet(url);
                    WxAccessToken accessToken = WxAccessToken.fromJson(result.getJson());
                    this.getWxMpConfigStorage().updateAccessToken(accessToken.getAccessToken(),
                            accessToken.getExpiresIn(), authorizer_appid);
                }
            }
        } finally {
            lock.unlock();
        }
        return this.getWxMpConfigStorage().getAccessToken(authorizer_appid);
    }

    private WxError HttpGet(String url) throws WxErrorException {
        try {
            HttpGet httpGet = new HttpGet(url);
            if (this.httpProxy != null) {
                RequestConfig config = RequestConfig.custom().setProxy(this.httpProxy).build();
                httpGet.setConfig(config);
            }
            try (CloseableHttpResponse response = getHttpclient().execute(httpGet)) {
                String resultContent = new BasicResponseHandler().handleResponse(response);
                WxError error = WxError.fromJson(resultContent);
                if (error.getErrorCode() != 0) {
                    throw new WxErrorException(error);
                }
                error.setJson(resultContent);
                return error;
            } finally {
                httpGet.releaseConnection();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getJsapiTicket(final String... authorizerAppid) throws WxErrorException {
        return getJsapiTicket(false, authorizerAppid);
    }

    @Override
    public String getJsapiTicket(boolean forceRefresh, String... authorizerAppid) throws WxErrorException {
        Lock lock = this.getWxMpConfigStorage().getJsapiTicketLock();
        try {
            lock.lock();

            if (forceRefresh) {
                this.getWxMpConfigStorage().expireJsapiTicket(authorizerAppid);
            }
            if (this.getWxMpConfigStorage().isJsapiTicketExpired(authorizerAppid)) {
                String url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi";
                String responseContent = execute(new SimpleGetRequestExecutor(), url, null, authorizerAppid);
                JsonElement tmpJsonElement = JSON_PARSER.parse(responseContent);
                JsonObject tmpJsonObject = tmpJsonElement.getAsJsonObject();
                String jsapiTicket = tmpJsonObject.get("ticket").getAsString();
                int expiresInSeconds = tmpJsonObject.get("expires_in").getAsInt();
                this.getWxMpConfigStorage().updateJsapiTicket(jsapiTicket, expiresInSeconds, authorizerAppid);
            }
        } finally {
            lock.unlock();
        }
        return this.getWxMpConfigStorage().getJsapiTicket(authorizerAppid);
    }

    @Override
    public WxJsapiSignature createJsapiSignature(String url, String... authorizerAppid) throws WxErrorException {
        long timestamp = System.currentTimeMillis() / 1000;
        String noncestr = RandomUtils.getRandomStr();
        String jsapiTicket = getJsapiTicket(false, authorizerAppid);
        String signature = SHA1.genWithAmple("jsapi_ticket=" + jsapiTicket,
                "noncestr=" + noncestr, "timestamp=" + timestamp, "url=" + url);
        WxJsapiSignature jsapiSignature = new WxJsapiSignature();
        if (authorizerAppid.length == 0) {
            jsapiSignature.setAppId(this.getWxMpConfigStorage().getAppId());
        } else {
            jsapiSignature.setAppId(authorizerAppid[0]);
        }
        jsapiSignature.setTimestamp(timestamp);
        jsapiSignature.setNonceStr(noncestr);
        jsapiSignature.setUrl(url);
        jsapiSignature.setSignature(signature);
        return jsapiSignature;
    }

    @Override
    public WxMpMassUploadResult massNewsUpload(WxMpMassNews news) throws WxErrorException {
        String url = "https://api.weixin.qq.com/cgi-bin/media/uploadnews";
        String responseContent = this.post(url, news.toJson());
        return WxMpMassUploadResult.fromJson(responseContent);
    }

    @Override
    public WxMpMassUploadResult massVideoUpload(WxMpMassVideo video) throws WxErrorException {
        String url = "https://api.weixin.qq.com/cgi-bin/media/uploadvideo";
        String responseContent = this.post(url, video.toJson());
        return WxMpMassUploadResult.fromJson(responseContent);
    }

    @Override
    public WxMpMassSendResult massGroupMessageSend(WxMpMassTagMessage message) throws WxErrorException {
        String url = "https://api.weixin.qq.com/cgi-bin/message/mass/sendall";
        String responseContent = this.post(url, message.toJson());
        return WxMpMassSendResult.fromJson(responseContent);
    }

    @Override
    public WxMpMassSendResult massOpenIdsMessageSend(WxMpMassOpenIdsMessage message) throws WxErrorException {
        String url = "https://api.weixin.qq.com/cgi-bin/message/mass/send";
        String responseContent = this.post(url, message.toJson());
        return WxMpMassSendResult.fromJson(responseContent);
    }

    @Override
    public WxMpMassSendResult massMessagePreview(WxMpMassPreviewMessage wxMpMassPreviewMessage) throws Exception {
        String url = "https://api.weixin.qq.com/cgi-bin/message/mass/preview";
        String responseContent = this.post(url, wxMpMassPreviewMessage.toJson());
        return WxMpMassSendResult.fromJson(responseContent);
    }

    @Override
    public String shortUrl(String long_url) throws WxErrorException {
        String url = "https://api.weixin.qq.com/cgi-bin/shorturl";
        JsonObject o = new JsonObject();
        o.addProperty("action", "long2short");
        o.addProperty("long_url", long_url);
        String responseContent = this.post(url, o.toString());
        JsonElement tmpJsonElement = JSON_PARSER.parse(responseContent);
        return tmpJsonElement.getAsJsonObject().get("short_url").getAsString();
    }

    @Override
    public WxMpSemanticQueryResult semanticQuery(WxMpSemanticQuery semanticQuery) throws WxErrorException {
        String url = "https://api.weixin.qq.com/semantic/semproxy/search";
        String responseContent = this.post(url, semanticQuery.toJson());
        return WxMpSemanticQueryResult.fromJson(responseContent);
    }

    @Override
    public String oauth2buildAuthorizationUrl(String redirectURI, String scope, String state) {
        StringBuilder url = new StringBuilder();
        url.append("https://open.weixin.qq.com/connect/oauth2/authorize?");
        url.append("appid=").append(this.getWxMpConfigStorage().getAppId());
        url.append("&redirect_uri=").append(URIUtil.encodeURIComponent(redirectURI));
        url.append("&response_type=code");
        url.append("&scope=").append(scope);
        if (state != null) {
            url.append("&state=").append(state);
        }
        url.append("#wechat_redirect");
        return url.toString();
    }

    @Override
    public String buildQrConnectUrl(String redirectURI, String scope,
                                    String state) {
        StringBuilder url = new StringBuilder();
        url.append("https://open.weixin.qq.com/connect/qrconnect?");
        url.append("appid=").append(this.getWxMpConfigStorage().getAppId());
        url.append("&redirect_uri=").append(URIUtil.encodeURIComponent(redirectURI));
        url.append("&response_type=code");
        url.append("&scope=").append(scope);
        if (state != null) {
            url.append("&state=").append(state);
        }

        url.append("#wechat_redirect");
        return url.toString();
    }

    private WxMpOAuth2AccessToken getOAuth2AccessToken(StringBuilder url) throws WxErrorException {
        try {
            RequestExecutor<String, String> executor = new SimpleGetRequestExecutor();
            String responseText = executor.execute(this.getHttpclient(), this.httpProxy, url.toString(), null);
            return WxMpOAuth2AccessToken.fromJson(responseText);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public WxMpOAuth2AccessToken oauth2getAccessToken(String code, String... authorizerAppid) throws WxErrorException {
        StringBuilder url = new StringBuilder();
        if (isThree(authorizerAppid)) {
            url.append("https://api.weixin.qq.com/sns/oauth2/component/access_token?");
            url.append("appid=").append(authorizerAppid[0]);
            url.append("&code=").append(code);
            url.append("&grant_type=authorization_code");
            url.append("&component_appid=").append(this.getWxMpConfigStorage().getAppId());
            url.append("&component_access_token=").append(componentAccessTokenGet());
        } else {
            url.append("https://api.weixin.qq.com/sns/oauth2/access_token?");
            url.append("appid=").append(this.getWxMpConfigStorage().getAppId());
            url.append("&secret=").append(this.getWxMpConfigStorage().getSecret());
            url.append("&code=").append(code);
            url.append("&grant_type=authorization_code");
        }
        return this.getOAuth2AccessToken(url);
    }

    private boolean isThree(String... authorizerAppid) {
        if (authorizerAppid.length != 0 && authorizerAppid[0] != null) {
            return true;
        }
        return false;
    }

    @Override
    public WxMpOAuth2AccessToken oauth2refreshAccessToken(String refreshToken, String... authorizerAppid) throws WxErrorException {
        //https://api.weixin.qq.com/sns/oauth2/component/refresh_token?appid=APPID&grant_type=refresh_token&component_appid=COMPONENT_APPID&component_access_token=COMPONENT_ACCESS_TOKEN&refresh_token=REFRESH_TOKEN
        StringBuilder url = new StringBuilder();
        if (isThree(authorizerAppid)) {
            url.append("https://api.weixin.qq.com/sns/oauth2/component/refresh_token?");
            url.append("appid=").append(authorizerAppid[0]);
            url.append("&component_appid=").append(this.getWxMpConfigStorage().getAppId());
            url.append("&component_access_token=").append(componentAccessTokenGet());
        } else {
            url.append("https://api.weixin.qq.com/sns/oauth2/refresh_token?");
            url.append("appid=").append(this.getWxMpConfigStorage().getAppId());
        }
        url.append("&grant_type=refresh_token");
        url.append("&refresh_token=").append(refreshToken);
        return this.getOAuth2AccessToken(url);
    }

    @Override
    public WxMpUser oauth2getUserInfo(WxMpOAuth2AccessToken oAuth2AccessToken, String lang) throws WxErrorException {
        StringBuilder url = new StringBuilder();
        url.append("https://api.weixin.qq.com/sns/userinfo?");
        url.append("access_token=").append(oAuth2AccessToken.getAccessToken());
        url.append("&openid=").append(oAuth2AccessToken.getOpenId());
        if (lang == null) {
            url.append("&lang=zh_CN");
        } else {
            url.append("&lang=").append(lang);
        }
        try {
            RequestExecutor<String, String> executor = new SimpleGetRequestExecutor();
            String responseText = executor.execute(getHttpclient(), this.httpProxy, url.toString(), null);
            return WxMpUser.fromJson(responseText);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean oauth2validateAccessToken(WxMpOAuth2AccessToken oAuth2AccessToken) {
        StringBuilder url = new StringBuilder();
        url.append("https://api.weixin.qq.com/sns/auth?");
        url.append("access_token=").append(oAuth2AccessToken.getAccessToken());
        url.append("&openid=").append(oAuth2AccessToken.getOpenId());

        try {
            RequestExecutor<String, String> executor = new SimpleGetRequestExecutor();
            executor.execute(getHttpclient(), this.httpProxy, url.toString(), null);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (WxErrorException e) {
            return false;
        }
        return true;
    }

    @Override
    public String[] getCallbackIP() throws WxErrorException {
        String url = "https://api.weixin.qq.com/cgi-bin/getcallbackip";
        String responseContent = get(url, null);
        JsonElement tmpJsonElement = JSON_PARSER.parse(responseContent);
        JsonArray ipList = tmpJsonElement.getAsJsonObject().get("ip_list").getAsJsonArray();
        String[] ipArray = new String[ipList.size()];
        for (int i = 0; i < ipList.size(); i++) {
            ipArray[i] = ipList.get(i).getAsString();
        }
        return ipArray;
    }

    @Override
    public String get(String url, String queryParam, String... appid) throws WxErrorException {
        return execute(new SimpleGetRequestExecutor(), url, queryParam, appid);
    }


    @Override
    public String post(String url, String postData, String... appid) throws WxErrorException {
        return execute(new SimplePostRequestExecutor(), url, postData, appid);
    }

    /**
     * 向微信端发送请求，在这里执行的策略是当发生access_token过期时才去刷新，然后重新执行请求，而不是全局定时请求
     */
    @Override
    public <T, E> T execute(RequestExecutor<T, E> executor, String uri, E data, String... appid) throws WxErrorException {
        int retryTimes = 0;
        do {
            try {
                T result = executeInternal(executor, uri, data, appid);
                this.log.debug("\n[URL]:  {}\n[PARAMS]: {}\n[RESPONSE]: {}", uri, data, result);
                return result;
            } catch (WxErrorException e) {
                if (retryTimes + 1 > this.maxRetryTimes) {
                    this.log.warn("重试达到最大次数【{}】", maxRetryTimes);
                    //最后一次重试失败后，直接抛出异常，不再等待
                    throw new RuntimeException("微信服务端异常，超出重试次数");
                }

                WxError error = e.getError();
                // -1 系统繁忙, 1000ms后重试
                if (error.getErrorCode() == -1) {
                    int sleepMillis = this.retrySleepMillis * (1 << retryTimes);
                    try {
                        this.log.warn("微信系统繁忙，{} ms 后重试(第{}次)", sleepMillis, retryTimes + 1);
                        Thread.sleep(sleepMillis);
                    } catch (InterruptedException e1) {
                        throw new RuntimeException(e1);
                    }
                } else {
                    throw e;
                }
            }
        } while (retryTimes++ < this.maxRetryTimes);

        this.log.warn("重试达到最大次数【{}】", this.maxRetryTimes);
        throw new RuntimeException("微信服务端异常，超出重试次数");
    }

    Gson gson = new Gson();

    protected synchronized <T, E> T executeInternal(RequestExecutor<T, E> executor, String uri, E data, String... appid) throws WxErrorException {
        if (uri.indexOf("access_token=") != -1) {
            throw new IllegalArgumentException("uri参数中不允许有access_token: " + uri);
        }

        String accessToken = null;
        String authorizer_appid = null;

        if (appid != null && appid.length > 0) {
            authorizer_appid = appid[0];
        }

        accessToken = getAccessToken(false, authorizer_appid);
        if (accessToken == null) {
            this.log.error(" accessToken is null authorizer_appid:" + authorizer_appid);
            return null;
        }
        String uriWithAccessToken = uri;
        uriWithAccessToken += uri.indexOf('?') == -1 ? "?access_token=" + accessToken : "&access_token=" + accessToken;
        try {
            return executor.execute(getHttpclient(), this.httpProxy, uriWithAccessToken, data);
        } catch (WxErrorException e) {
            WxError error = e.getError();
      /*
       * 发生以下情况时尝试刷新access_token
       * 40001 获取access_token时AppSecret错误，或者access_token无效
       * 42001 access_token超时
       */
            if (error.getErrorCode() == 42001 || error.getErrorCode() == 40001) {
                // 强制设置wxMpConfigStorage它的access token过期了，这样在下一次请求里就会刷新access token
                this.getWxMpConfigStorage().expireAccessToken(authorizer_appid);
                if (this.getWxMpConfigStorage().autoRefreshToken(authorizer_appid)) {
                    return this.execute(executor, uri, data, authorizer_appid);
                }
            }
            if (error.getErrorCode() != 0) {
                this.log.error("\n[URL]:  {}\n[PARAMS]: {}\n[RESPONSE]: {}", uri, data, error);
                throw new WxErrorException(error);
            }
            return null;
        } catch (IOException e) {
            this.log.error("\n[URL]:  {}\n[PARAMS]: {}\n[EXCEPTION]: {}", uri, data, e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    public HttpHost getHttpProxy() {
        return this.httpProxy;
    }

    public CloseableHttpClient getHttpclient() {
        return this.httpClient;
    }

    private void initHttpClient() {
        WxMpConfigStorage configStorage = this.getWxMpConfigStorage();
        ApacheHttpClientBuilder apacheHttpClientBuilder = configStorage.getApacheHttpClientBuilder();
        if (null == apacheHttpClientBuilder) {
            apacheHttpClientBuilder = DefaultApacheHttpClientBuilder.get();
        }

        apacheHttpClientBuilder.httpProxyHost(configStorage.getHttpProxyHost())
                .httpProxyPort(configStorage.getHttpProxyPort())
                .httpProxyUsername(configStorage.getHttpProxyUsername())
                .httpProxyPassword(configStorage.getHttpProxyPassword());

        if (configStorage.getHttpProxyHost() != null && configStorage.getHttpProxyPort() > 0) {
            this.httpProxy = new HttpHost(configStorage.getHttpProxyHost(), configStorage.getHttpProxyPort());
        }

        this.httpClient = apacheHttpClientBuilder.build();
    }

    @Override
    public WxMpConfigStorage getWxMpConfigStorage() {
        return this.wxMpConfigStorage;
    }

    @Override
    public void setWxMpConfigStorage(WxMpConfigStorage wxConfigProvider) {
        this.wxMpConfigStorage = wxConfigProvider;
        this.initHttpClient();
    }

    @Override
    public void setRetrySleepMillis(int retrySleepMillis) {
        this.retrySleepMillis = retrySleepMillis;
    }

    @Override
    public void setMaxRetryTimes(int maxRetryTimes) {
        this.maxRetryTimes = maxRetryTimes;
    }

    @Override
    public WxMpKefuService getKefuService() {
        return this.kefuService;
    }

    @Override
    public WxMpMaterialService getMaterialService() {
        return this.materialService;
    }

    @Override
    public WxMpMenuService getMenuService() {
        return this.menuService;
    }

    @Override
    public WxMpUserService getUserService() {
        return this.userService;
    }

    @Override
    public WxMpUserTagService getUserTagService() {
        return this.tagService;
    }

    @Override
    public WxMpQrcodeService getQrcodeService() {
        return this.qrCodeService;
    }

    @Override
    public WxMpCardService getCardService() {
        return this.cardService;
    }

    @Override
    public WxMpDataCubeService getDataCubeService() {
        return this.dataCubeService;
    }

    @Override
    public WxMpUserBlacklistService getBlackListService() {
        return this.blackListService;
    }

    @Override
    public WxMpStoreService getStoreService() {
        return this.storeService;
    }

    @Override
    public WxMpTemplateMsgService getTemplateMsgService() {
        return this.templateMsgService;
    }

    @Override
    public WxMpDeviceService getDeviceService() {
        return this.deviceService;
    }

    @Override
    public String componentAccessTokenGet() throws WxErrorException {
        String component_appid = wxMpConfigStorage.getAppId();
        String token = String.format(COMPONENT_ACCESS_TOKEN, component_appid);
        String component_access_token = cacheService.get(token);
        if (component_access_token != null)
            return component_access_token;
        String ticket = cacheService.get(String.format(COMPONENT_VERIFY_TICKET, component_appid));
        if (ticket == null)
            return null;
        JsonObject object = new JsonObject();
        object.addProperty("component_appid", component_appid);
        object.addProperty("component_appsecret", wxMpConfigStorage.getSecret());
        object.addProperty("component_verify_ticket", ticket);
        JsonObject jsonObject = HttpUtils.POST("https://api.weixin.qq.com/cgi-bin/component/api_component_token", object.toString());
        if (jsonObject != null && jsonObject.get("component_access_token") != null) {
            component_access_token = jsonObject.get("component_access_token").getAsString();
            cacheService.set(token, component_access_token);
            cacheService.expire(token, jsonObject.get("expires_in").getAsLong());
            return component_access_token;
        }
        throw new WxErrorException(getWxError(jsonObject));
    }

    private WxError getWxError(JsonObject jsonObject) {
        log.error(jsonObject.toString());
        return WxError.newBuilder().setErrorCode(jsonObject.get("errcode").getAsInt()).setErrorMsg(jsonObject.get("errmsg").getAsString()).build();
    }

    /**
     * 使用授权码换取公众号的接口调用凭据和授权信息
     * 授权方接口调用凭据（在授权的公众号具备API权限时，才有此返回值），也简称为令牌
     */
    public String authorizerAccessTokenGet(String authorizer_appid) throws WxErrorException {
        //查询数据库
        String authorizer_refresh_token = authorizerRefreshTokenGet(wxMpConfigStorage.getAppId(), authorizer_appid);
        if (authorizer_refresh_token != null) {
            String authorizer_access_token = api_authorizer_tokenGet(authorizer_appid, authorizer_refresh_token);
            if (authorizer_access_token != null)
                return authorizer_refresh_token;
        }
        throw new WxErrorException(WxError.newBuilder().setErrorCode(4343).setErrorMsg("需要重新授权").build());
    }

    /**
     * 获取（刷新）授权公众号的接口调用凭据（令牌）
     *
     * @param authorizer_appid
     * @param authorizer_refresh_token
     * @return
     */
    private String api_authorizer_tokenGet(final String authorizer_appid, String authorizer_refresh_token) throws WxErrorException {
        String token = componentAccessTokenGet();
        JsonObject object = new JsonObject();
        object.addProperty("component_appid", wxMpConfigStorage.getAppId());
        object.addProperty("authorizer_appid", authorizer_appid);
        object.addProperty("authorizer_refresh_token", authorizer_refresh_token);
        JsonObject jsonObject = HttpUtils.POST("https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token?component_access_token=" + token, object.toString());
        return updateAccessToken(jsonObject, authorizer_appid);
    }


    public String updateAccessToken(JsonObject jsonObject, String authorizer_appid) throws WxErrorException {
        JsonElement jsonElement = jsonObject.get("authorizer_access_token");
        if (jsonElement != null) {
            String authorizer_access_token = jsonElement.getAsString();
            String authorizer_refresh_token = jsonObject.get("authorizer_refresh_token").getAsString();
            wxMpConfigStorage.updateAccessToken(authorizer_access_token, jsonObject.get("expires_in").getAsInt(), authorizer_appid);
            wxMpConfigStorage.updateRefreshTokenKey(authorizer_refresh_token, jsonObject.get("expires_in").getAsInt(), authorizer_appid);
            authorizerTokenUpdate(authorizer_access_token, authorizer_refresh_token, authorizer_appid, wxMpConfigStorage.getAppId());
            return authorizer_access_token;
        }
        throw new WxErrorException(getWxError(jsonObject));
    }


    @Override
    public String preAuthCode() throws WxErrorException {
        //https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=xxx
        JsonObject object = new JsonObject();
        object.addProperty("component_appid", wxMpConfigStorage.getAppId());
        String token = componentAccessTokenGet();
        JsonObject jsonObject = HttpUtils.POST("https://api.weixin.qq.com/cgi-bin/component/api_create_preauthcode?component_access_token=" + token, object.toString());
        String pre_auth_code = null;
        if (jsonObject != null && jsonObject.get("pre_auth_code") != null) {
            return jsonObject.get("pre_auth_code").getAsString();
        }
        throw new WxErrorException(getWxError(jsonObject));
    }

    @Override
    public String authorizerRefreshTokenGet(String component_appid, String authorizer_appid) {
        return null;
    }

    @Override
    public boolean authorizerTokenUpdate(String authorizer_access_token, String authorizer_refresh_token, String authorizer_appid, String component_appid) {
        return false;
    }


    public boolean authorizerAccessTokenUpdate(String authorizer_appid, String authorization_code) throws WxErrorException {
        String token = componentAccessTokenGet();
        //查询数据库
        JsonObject object = new JsonObject();
        object.addProperty("component_appid", wxMpConfigStorage.getAppId());
        object.addProperty("authorization_code", authorization_code);
        JsonObject jsonObject = HttpUtils.POST("https://api.weixin.qq.com/cgi-bin/component/api_query_auth?component_access_token=" + token, object.toString());
        JsonObject json = jsonObject.getAsJsonObject("authorization_info");
        if (json == null) {
            int errcode = jsonObject.get("errcode").getAsInt();
            log.error(jsonObject.toString());
            if (errcode == 61010) {//code 过期
                String key = String.format(AUTH_CODE, wxMpConfigStorage.getAppId(), authorizer_appid);
                cacheService.delete(key);
            }
            throw new WxErrorException(getWxError(jsonObject));
        }
        updateAccessToken(json, authorizer_appid);
        return true;
    }

}
