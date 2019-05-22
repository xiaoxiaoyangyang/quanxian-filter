package com.sensetime.fis.senseguard.filter.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.sensetime.fis.senseguard.filter.oauth2filter.Oauth2Filter;

/**
 * @author guozhiyang_vendor
 *
 *
 */
@Configuration
public class FilterConfig {

    @Bean(name = "ret")
    public RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate(simpleClientHttpRequestFactory());
        return restTemplate;
    }

    public ClientHttpRequestFactory simpleClientHttpRequestFactory() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setReadTimeout(5000);
        factory.setConnectTimeout(5000);
        return factory;
    }

    @Bean
    public Oauth2Filter getOauth2Filter(){
        return new Oauth2Filter();
    }
}
