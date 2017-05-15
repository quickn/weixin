package me.chanjar.weixin.mp.api;

import me.chanjar.weixin.common.bean.WxAccessToken;
import me.chanjar.weixin.common.util.http.ApacheHttpClientBuilder;

import java.io.File;
import java.util.concurrent.locks.Lock;

/**
 * 微信客户端配置存储
 *
 * @author chanjarster
 */
public interface WxMpConfigStorage {

  String getAccessToken(String ... authorizerAppid);

  Lock getAccessTokenLock();

  boolean isAccessTokenExpired(String ... authorizerAppid);

  /**
   * 强制将access token过期掉
   */
  void expireAccessToken(String ... authorizerAppid);

  /**
   * 应该是线程安全的
   *
   * @param accessToken 要更新的WxAccessToken对象
   */
  void updateAccessToken(WxAccessToken accessToken,String ... authorizerAppid);

  /**
   * 应该是线程安全的
   *
   * @param accessToken      新的accessToken值
   * @param expiresInSeconds 过期时间，以秒为单位
   */
  void updateAccessToken(String accessToken, int expiresInSeconds,String ... authorizerAppid);

  void updateRefreshTokenKey(String accessToken, int expiresInSeconds,String authorizerAppid);

  String getJsapiTicket(String ... authorizerAppid);

  Lock getJsapiTicketLock();

  boolean isJsapiTicketExpired(String ... authorizerAppid);

  /**
   * 强制将jsapi ticket过期掉
   */
  void expireJsapiTicket(String ... authorizerAppid);

  /**
   * 应该是线程安全的
   *
   * @param jsapiTicket      新的jsapi ticket值
   * @param expiresInSeconds 过期时间，以秒为单位
   */
  void updateJsapiTicket(String jsapiTicket, int expiresInSeconds,String ... authorizerAppid);

  String getCardApiTicket();

  Lock getCardApiTicketLock();

  boolean isCardApiTicketExpired();

  /**
   * 强制将卡券api ticket过期掉
   */
  void expireCardApiTicket();

  /**
   * 应该是线程安全的
   *
   * @param cardApiTicket    新的cardApi ticket值
   * @param expiresInSeconds 过期时间，以秒为单位
   */
  void updateCardApiTicket(String cardApiTicket, int expiresInSeconds);

  String getAppId();

  String getSecret();

  String getToken();

  String getAesKey();

  long getExpiresTime();

  String getOauth2redirectUri();

  String getHttpProxyHost();

  int getHttpProxyPort();

  String getHttpProxyUsername();

  String getHttpProxyPassword();

  File getTmpDirFile();

  /**
   * http client builder
   *
   * @return ApacheHttpClientBuilder
   */
  ApacheHttpClientBuilder getApacheHttpClientBuilder();

  /**
   * 是否自动刷新token
   */
  boolean autoRefreshToken(String ... authorizer_appid);

}
