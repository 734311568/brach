package com.aws.codestar.projecttemplates.service;

import java.io.IOException;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import javax.servlet.http.HttpSession;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.aws.codestar.projecttemplates.configuration.AuthHttpClient;


public interface IApiService {
	
	/**
	 * 呼叫 ../stories/" + id + "/storyComment/.. 取得某故事之最新留言
	 *
	 * @param storyId
	 * @return DOM 字串
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws TransformerConfigurationException
	 * @throws TransformerException
	 */
	public JSONArray getStoryComment(String storyId);
	/**
	 * 呼叫 ../personnels/search/.. 尋找帳號是否存在, 存在傳回 JSONObject; 反之回傳null
	 *
	 * @param thirdParty
	 * @param userId
	 * @return 帳號相關資訊之JSONObject
	 * @throws ClientProtocolException
	 * @throws IOException
	 * @throws URISyntaxException
	 */
	public JSONObject findOneByThirdPartyId(String thirdParty, String userId);
	/**
	 * 呼叫 ../personnels/search/findOneByEmail 尋找帳號是否存在, 存在傳回 JSONObject;
	 * 反之回傳null
	 *
	 * @param email
	 * @return
	 * @throws URISyntaxException
	 * @throws IOException
	 */
	public JSONObject findOneByEmail(String email);

	/**
	 *
	 * @param nickname
	 * @param facebookId
	 * @param googleId
	 * @param lineId
	 * @param email
	 * @param lastname
	 * @param firstname
	 * @param birth
	 * @param gender
	 * @param storeName
	 * @return
	 * @throws ClientProtocolException
	 * @throws IOException
	 */
	public String registerUser(String nickname, String facebookId, String googleId, String lineId, String email, String lastname, String firstname, String birth, String gender, String storeName);
	/*
		  {
		 	"content": "this is a story content.",		 
		 	"imgUrls":{"URL","URL","URL"}
		    "Author": "http://localhost:8080/personnels/1" 
		  }
	 */
	public String postStory(String content, String personnelsUri, String[] imgUrls);
	/*	
		{
			"story":"http://localhost:8080/stories/1",
			"who":"http://localhost:8080/personnels/1",
			"content":"oka"
		}
	 */
	public String postComments(String content, String personnelsUri, String storyUri);
	/*
	{	
		"url":"http://localhost:8080/img1",
		"content":"oka",
		"story":"http://localhost:8080/stories/1"
	}
	 */
	public String postImgUrl(String imgUrl, String content, String storyUrl);
}
