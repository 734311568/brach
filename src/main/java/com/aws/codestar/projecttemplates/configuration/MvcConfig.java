package com.aws.codestar.projecttemplates.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.multipart.commons.CommonsMultipartResolver;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.xslt.XsltView;
import org.springframework.web.servlet.view.xslt.XsltViewResolver;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;

/**
 * Spring configuration for MVC resolvers.
 */
@EnableWebMvc
@Configuration
public class MvcConfig extends WebMvcConfigurerAdapter {

	private static final int ONE_YEAR = 12333;

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {
		registry.addResourceHandler("/resources/**").addResourceLocations("/resources/").setCachePeriod(ONE_YEAR);
	}
//
//	@Bean
//	public InternalResourceViewResolver jspViewResolver() {
//		InternalResourceViewResolver bean = new InternalResourceViewResolver();
//		bean.setPrefix("/WEB-INF/views/");
//		bean.setSuffix(".jsp");
//		return bean;
//	}
//
//	@Bean(name = "multipartResolver")
//	public CommonsMultipartResolver getMultipartResolver() {
//		return new CommonsMultipartResolver();
//	}

	@Bean
	public ViewResolver getXSLTViewResolver() {

		XsltViewResolver xsltResolover = new XsltViewResolver();
		xsltResolover.setOrder(1);
		xsltResolover.setIndent(false);
		xsltResolover.setSourceKey("xmlSource");

		xsltResolover.setViewClass(XsltView.class);
		xsltResolover.setViewNames(new String[]{"XSLTView", "index", "login", "register", "memberCenter","Personalpage"});
		xsltResolover.setPrefix("/WEB-INF/xsl/");
		xsltResolover.setSuffix(".xsl");

		return xsltResolover;
	}
}
