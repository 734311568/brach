package com.aws.codestar.projecttemplates.configuration;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisSentinelConfiguration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;



//import io.lettuce.core.AbstractRedisClient;

import java.time.Duration;

@Configuration
@EnableCaching
public class RedisConfig {

	final private String redisHostName = "localhost";
//	final private String redisHostName = "192.168.0.254";
//	final private String test2 = "192.168.0.253";
//	 final private String redisHostName =
//	 "redan-redis.sh0mts.0001.apse1.cache.amazonaws.com";
	final private int redisPort = 6379;
	final private String redisPrefix = "redan";
	
	
	@Bean
	RedisConnectionFactory jedisConnectionFactory() {
		RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration(redisHostName,
				redisPort);
		return new JedisConnectionFactory(redisStandaloneConfiguration);
	}

	@Bean(value = "redisTemplate")
	public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
		RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
		redisTemplate.setConnectionFactory(redisConnectionFactory);
		redisTemplate.setKeySerializer(new StringRedisSerializer());
		return redisTemplate;
	}

	@Primary
	@Bean(name = "cacheManager") // Default cache manager is infinite
	public CacheManager cacheManager(RedisConnectionFactory redisConnectionFactory) {
		return RedisCacheManager.builder(redisConnectionFactory)
				.cacheDefaults(RedisCacheConfiguration.defaultCacheConfig()
						.prefixKeysWith(redisPrefix)).build();
	}

//	@Bean(name = "cacheManager1Hour")
//	public CacheManager cacheManager1Hour(RedisConnectionFactory redisConnectionFactory) {
//		Duration expiration = Duration.ofHours(1);
//		return RedisCacheManager.builder(redisConnectionFactory)
//				.cacheDefaults(
//						RedisCacheConfiguration.defaultCacheConfig()
//						.prefixKeysWith(redisPrefix)
//						.entryTtl(expiration))
//				.build();
//	}

}
