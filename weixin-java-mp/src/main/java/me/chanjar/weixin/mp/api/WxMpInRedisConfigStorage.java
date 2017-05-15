package me.chanjar.weixin.mp.api;

import redis.clients.jedis.Jedis;

/**
 * 基于Redis的微信配置provider
 *
 * @author lly835
 */
@SuppressWarnings("hiding")
public class WxMpInRedisConfigStorage extends WxMpInMemoryConfigStorage {

    private final static String ACCESS_TOKEN_KEY = "wechat_access_token_";

    private final static String JSAPI_TICKET_KEY = "wechat_jsapi_ticket_";

    private final static String CARDAPI_TICKET_KEY = "wechat_cardapi_ticket_";

    private static String COMPONENT_VERIFY_TICKET = "component_verify_ticket_%s";
    private static String AUTH_CODE = "auth_code_%s_%s";

    protected Jedis jedis;

    @Override
    public String getAccessToken(String ... authorizer_appid) {
        return jedis.get(ACCESS_TOKEN_KEY.concat(appId));
    }

    @Override
    public boolean isAccessTokenExpired(String ... authorizer_appid) {
        return getAccessToken(accessToken) == null ? true : false;
    }

    @Override
    public synchronized void updateAccessToken(String accessToken, int expiresInSeconds,String ... authorizer_appid) {
        jedis.set(ACCESS_TOKEN_KEY.concat(appId), accessToken);
        jedis.expire(ACCESS_TOKEN_KEY.concat(appId), expiresInSeconds - 200);
    }

    @Override
    public void expireAccessToken(String ... authorizer_appid) {
        jedis.expire(ACCESS_TOKEN_KEY.concat(appId), 0);
    }

    @Override
    public String getJsapiTicket(String... authorizer_appid) {
        return jedis.get(JSAPI_TICKET_KEY.concat(appId));
    }

    @Override
    public boolean isJsapiTicketExpired(String... authorizer_appid) {
        return getJsapiTicket() == null ? true : false;
    }

    @Override
    public synchronized void updateJsapiTicket(String jsapiTicket, int expiresInSeconds,String... authorizer_appid) {
        jedis.set(JSAPI_TICKET_KEY.concat(appId), jsapiTicket);
        jedis.expire(JSAPI_TICKET_KEY.concat(appId), expiresInSeconds - 200);
    }

    @Override
    public void expireJsapiTicket(String... authorizer_appid) {
        jedis.expire(JSAPI_TICKET_KEY.concat(appId), 0);
    }

    /**
     * 卡券api_ticket
     */
    @Override
    public String getCardApiTicket() {
        return jedis.get(CARDAPI_TICKET_KEY.concat(appId));
    }

    @Override
    public boolean isCardApiTicketExpired() {
        return getCardApiTicket() == null ? true : false;
    }

    @Override
    public synchronized void updateCardApiTicket(String cardApiTicket, int expiresInSeconds) {
        jedis.set(CARDAPI_TICKET_KEY.concat(appId), cardApiTicket);
        jedis.expire(CARDAPI_TICKET_KEY.concat(appId), expiresInSeconds - 200);
    }

    @Override
    public void expireCardApiTicket() {
        jedis.expire(CARDAPI_TICKET_KEY.concat(appId), 0);
    }

    public void setJedis(Jedis jedis) {
        this.jedis = jedis;
    }


    public String authorization_codeGet(String authorizer_appid) {
        String authorization_code = jedis.get(String.format(AUTH_CODE, appId, authorizer_appid));
        if (authorization_code != null) {
            return authorization_code;
        }
        return null;
    }
}