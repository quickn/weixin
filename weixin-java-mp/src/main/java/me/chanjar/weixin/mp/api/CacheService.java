package me.chanjar.weixin.mp.api;

/**
 * Created by Json on 2017/5/9.
 */
public interface CacheService {

    String get(final String key);

    Boolean set(final String key, final String value, final long... seconds);

    Boolean delete(final String key);

    Boolean expire(String key, long expires_in);

}
