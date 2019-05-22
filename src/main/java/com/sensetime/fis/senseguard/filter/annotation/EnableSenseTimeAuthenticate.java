package com.sensetime.fis.senseguard.filter.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import com.sensetime.fis.senseguard.filter.config.FilterConfig;

/**
 * @author guozhiyang_vendor
 */
@Import({FilterConfig.class})
@Retention(value = RetentionPolicy.RUNTIME)
@Target(value = { ElementType.TYPE })
@Documented
public @interface EnableSenseTimeAuthenticate {
}
