package com.aws.codestar.projecttemplates.configuration;

import java.io.IOException;
import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.http.Header;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class AuthHttpClient {
	CloseableHttpClient httpclient = HttpClients.createDefault();
	// String host = "https://socialmall-basic.herokuapp.com/";
	String host = "https://redan-api.herokuapp.com/";

	public String getHost() {
		return host;
	}

	class AuthObj {

		private String date;
		private String token;

		public AuthObj() {
			super();
			this.date = String.valueOf(System.currentTimeMillis());
			try {
				this.token = com.aws.codestar.projecttemplates.suppot.Skein512Small.hash(date);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		public String getDate() {
			return date;
		}

		public String getToken() {
			return token;
		}
	}

	private Header bulidAuthObj(AuthObj authObj) {
		return BasicScheme.authenticate(new UsernamePasswordCredentials(authObj.getDate(), authObj.getToken()), "UTF-8",
				false);
	}

	public HttpGet bulidHttpGet(String path) {
		HttpGet httpGet = new HttpGet(host + path);
		httpGet.addHeader(bulidAuthObj(new AuthObj()));
		return httpGet;
	}

	public HttpGet bulidHttpViaURI(URI uri) {
		HttpGet httpGet = new HttpGet(uri);
		httpGet.addHeader(bulidAuthObj(new AuthObj()));
		return httpGet;
	}
	public HttpPost bulidHttpPost(String path) {
		HttpPost httpPost = new HttpPost(host + path);
		httpPost.addHeader(bulidAuthObj(new AuthObj()));
		return httpPost;
	}

	public HttpPut bulidHttpPut(String path) {
		HttpPut httpPut = new HttpPut(host + path);
		httpPut.addHeader(bulidAuthObj(new AuthObj()));
		return httpPut;
	}

}
