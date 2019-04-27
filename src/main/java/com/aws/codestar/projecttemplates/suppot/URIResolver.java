package com.aws.codestar.projecttemplates.suppot;

import java.io.*;
import java.util.*;
import javax.servlet.ServletContext;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import org.springframework.web.context.support.ServletContextResource;

/**
 * @author P-C Lin (a.k.a 高科技黑手)
 */
public class URIResolver implements javax.xml.transform.URIResolver {

	/**
	 * Servlet Context to pull the file from
	 */
	@org.springframework.beans.factory.annotation.Autowired
	private ServletContext servletContext;

	/**
	 * The Default path to look for the file
	 */
	private String prefix;

	/**
	 * Simple Cache to improve speed
	 */
	@SuppressWarnings({"FieldMayBeFinal"})
	private Map cache;

	/**
	 * 預設建構子
	 */
	public URIResolver() {
		this.cache = new HashMap();
		this.prefix = "/WEB-INF/xsl/";
	}

	/**
	 * @param prefix
	 */
	public URIResolver(String prefix) {
		this.cache = new HashMap();
		this.prefix = prefix;
	}

	/**
	 * @param servletContext
	 */
	public URIResolver(ServletContext servletContext) {
		this.cache = new HashMap();
		this.prefix = "/WEB-INF/xsl/";
		this.servletContext = servletContext;
	}

	/**
	 * @return 基底路徑
	 */
	public String getPrefix() {
		return prefix;
	}

	/**
	 * @param prefix 基底路徑
	 */
	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

	/**
	 * @param href 相對路徑
	 * @param base 基底路徑
	 * @return 參考用路徑
	 */
	@Override
	@SuppressWarnings({"BroadCatchBlock", "TooBroadCatch", "UnusedAssignment", "null"})
	public Source resolve(String href, String base) {
		Source source = null;
		if (cache.containsKey(href)) {
			source = (Source) cache.get(href);
		} else {
			ServletContextResource servletContextResource = null;
			InputStream inputStream = null;
			try {
				servletContextResource = new ServletContextResource(servletContext, prefix.concat(href));
				inputStream = servletContextResource.getInputStream();
				source = new StreamSource(inputStream);
			} catch (IOException ioException) {
				ioException.printStackTrace(System.err);
			} finally {
				try {
					inputStream.close();
				} catch (Exception exceptions) {
					exceptions.printStackTrace(System.err);
				}
			}
		}
		return source;
	}
}
