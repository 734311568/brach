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

@Component
public class ApiService {

	public Document getStory(HttpSession httpSession) throws ParserConfigurationException, ClientProtocolException, IOException, TransformerConfigurationException, TransformerException {
		HttpGet httpGet = new AuthHttpClient().bulidHttpGet("stories/");

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		Document document = documentBuilder.newDocument();

		CloseableHttpResponse closeableHttpResponse = HttpClients.createDefault().execute(httpGet);
		try {
			HttpEntity httpEntity = closeableHttpResponse.getEntity();
			if (httpEntity != null) {
				String stringOfEntity = EntityUtils.toString(httpEntity, "UTF-8");
				JSONObject jSONObjectOfEntity = new JSONObject(stringOfEntity);
				String stringOfEmbedded = jSONObjectOfEntity.get("_embedded").toString();

				Element elementOfDocument = document.createElement("document");
				document.appendChild(elementOfDocument);

				//將目前已登入的 user 資訊(from httpSession)寫進 document.attribute
				if (httpSession.getAttribute("me") != null) {
					elementOfDocument.setAttribute("me", httpSession.getAttribute("me").toString());
				}
				if (httpSession.getAttribute("id") != null) {
					elementOfDocument.setAttribute("id", httpSession.getAttribute("id").toString());
				}
				if (httpSession.getAttribute("personnelHref") != null) {
					elementOfDocument.setAttribute("personnelHref", httpSession.getAttribute("personnelHref").toString());
				}
				if (httpSession.getAttribute("thirdParty") != null) {
					elementOfDocument.setAttribute("thirdParty", httpSession.getAttribute("thirdParty").toString());
				}
				if (httpSession.getAttribute("nickname") != null) {
					elementOfDocument.setAttribute("nickname", httpSession.getAttribute("nickname").toString());
				}

				//rank 0
				//create stories---start
				Element elementOfStories = document.createElement("stories");
//				elementOfStories.setAttribute("status", new JSONObject(stringOfEntity).get("status").toString());
				elementOfDocument.appendChild(elementOfStories);

				JSONArray jSONArrayOfStories = new JSONObject(stringOfEmbedded).getJSONArray("stories");
				for (int i = 0; i < jSONArrayOfStories.length(); i++) {
					JSONObject jSONObjectOfStory = jSONArrayOfStories.getJSONObject(i);

					//rank 1
					//create story---start
					Element elementOfStory = document.createElement("story");
					elementOfStory.setAttribute("id", jSONObjectOfStory.get("id").toString());
//					elementOfStory.setAttribute("emotions", jSONObjectOfStory.get("emotions").toString());
					elementOfStory.setAttribute("postedAt", jSONObjectOfStory.get("postedAt").toString());

					//rank 2
					//create story/author, story/content---start
					Element elementOfAuthor = document.createElement("author");
					elementOfAuthor.setAttribute("id", jSONObjectOfStory.getJSONObject("author").get("id").toString());
					elementOfAuthor.setAttribute("profileImgUrl", jSONObjectOfStory.getJSONObject("author").get("profileImgUrl").toString());
					elementOfAuthor.setAttribute("nickname", jSONObjectOfStory.getJSONObject("author").get("nickname").toString());
					elementOfStory.appendChild(elementOfAuthor);

					Element elementOfContent = document.createElement("content");
					elementOfContent.appendChild(document.createTextNode(jSONObjectOfStory.get("content").toString()));
					elementOfStory.appendChild(elementOfContent);

					String mode = "";
					Element elementOfStoryImages = document.createElement("storyImages");
					JSONArray jSONArrayOfStoryImages = jSONObjectOfStory.getJSONArray("storyImage");
					for (int j = 0; j < jSONArrayOfStoryImages.length(); j++) {
						JSONObject jSONObjectOfStoryImage = jSONArrayOfStoryImages.getJSONObject(j);

						Element elementOfUrl = document.createElement("url");
						String decodedURL = URLDecoder.decode(jSONObjectOfStoryImage.get("imgUrl").toString(), "UTF-8");
						elementOfUrl.appendChild(document.createTextNode(decodedURL));

						Element elementOfStoryImage = document.createElement("storyImage");

						if (j == 0) {
							mode = "carousel-item active";
						} else {
							mode = "carousel-item";
						}
						elementOfStoryImage.setAttribute("mode", mode);

						String count = String.valueOf(j);
						elementOfStoryImage.setAttribute("count", count);
						elementOfStoryImage.appendChild(elementOfUrl);
						elementOfStoryImages.appendChild(elementOfStoryImage);
					}
					elementOfStory.appendChild(elementOfStoryImages);

					Element elementOfHref = document.createElement("href");
					elementOfHref.appendChild(document.createTextNode(jSONObjectOfStory.getJSONObject("_links").getJSONObject("self").get("href").toString()));
					elementOfStory.appendChild(elementOfHref);
					//create story/author, story/content---end

					//rank 3
					//create comments---start
					Element elementOfComments = document.createElement("comments");
					JSONArray jSONArrayOfComments = jSONObjectOfStory.getJSONArray("storyComment");
					for (int j = 0; j < jSONArrayOfComments.length(); j++) {
						JSONObject jSONObjectOfComment = jSONArrayOfComments.getJSONObject(j);
						//rank 4
						//create comment---start
						Element elementOfComment = document.createElement("comment");
						elementOfComment.setAttribute("id", jSONObjectOfComment.get("id").toString());

						//rank 5
						//create comment/content, comment/who---start
						Element contentOfComment = document.createElement("content");
						contentOfComment.appendChild(document.createTextNode(jSONObjectOfComment.get("content").toString()));
						elementOfComment.appendChild(contentOfComment);

						Element whoOfComment = document.createElement("who");
						whoOfComment.setAttribute("id", jSONObjectOfComment.get("whoId").toString());
						whoOfComment.setAttribute("nickname", jSONObjectOfComment.get("who").toString());
						elementOfComment.appendChild(whoOfComment);
						//create comment/content, comment/who---end

						elementOfComments.appendChild(elementOfComment);
						//create comment---end
					}
					elementOfStory.appendChild(elementOfComments);
					//create comments---end

					elementOfStories.appendChild(elementOfStory);
					//create story---end
				}
				//create stories---end
			}
		} finally {
			closeableHttpResponse.close();
		}

		DOMSource domSource = new DOMSource(document);
		StringWriter writer = new StringWriter();
		StreamResult result = new StreamResult(writer);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.transform(domSource, result);
		System.out.println(writer.toString());
		return document;
	}
	
	/**
	 * 获取个人主页数据 personnels/search/findOneById 路径
	 *
	 * @param id 参数
	 * @return
	 */
	public Document getPersonnels(String id) throws ParserConfigurationException, IOException {

		//获取文档对象
		DocumentBuilderFactory newInstance = DocumentBuilderFactory.newInstance();
		DocumentBuilder newDocumentBuilder = newInstance.newDocumentBuilder();
		Document doc = newDocumentBuilder.newDocument();

		//创建根节点
		Element documentElement = doc.createElement("document");
		doc.appendChild(documentElement);

		HttpGet httpGet = new AuthHttpClient().bulidHttpGet("personnels/search/findOneById?id=" + id);
		//获取请求体
		CloseableHttpResponse execute = HttpClients.createDefault().execute(httpGet);
		HttpEntity entity = execute.getEntity();

		if (entity != null) {
			String string = EntityUtils.toString(entity, "UTF-8");

			//获取所有数据
			JSONObject object = new JSONObject(string);

			//获取非array的数据
			//coverImgUrl-背景图
			Element coverImgUrlElement = doc.createElement("coverImgUrl");
			coverImgUrlElement.setAttribute("src", object.get("coverImgUrl").toString());
			documentElement.appendChild(coverImgUrlElement);

			//profileImgUrl-头像
			Element profileImgUrlElement = doc.createElement("profileImgUrl");
			profileImgUrlElement.setAttribute("src", object.get("profileImgUrl").toString());
			documentElement.appendChild(profileImgUrlElement);

			//profileText-简介
			Element profileTextElement = doc.createElement("profileText");
			profileTextElement.appendChild(doc.createTextNode(object.get("profileText").toString()));
			documentElement.appendChild(profileTextElement);

			//nickname-用户名
			Element nicknameElement = doc.createElement("nickname");
			nicknameElement.appendChild(doc.createTextNode(object.get("nickname").toString()));
			documentElement.appendChild(nicknameElement);

			//userStoryCount-发表文章数量
			Element userStoryCountElement = doc.createElement("userStoryCount");
			userStoryCountElement.appendChild(doc.createTextNode(object.get("userStoryCount").toString()));
			documentElement.appendChild(userStoryCountElement);

			//followerCount-追随者数量
			Element followerCountElement = doc.createElement("followerCount");
			followerCountElement.appendChild(doc.createTextNode(object.get("followerCount").toString()));
			documentElement.appendChild(followerCountElement);

			//userStory-发表的文章
			Element userStoryElement = doc.createElement("userStory");
			documentElement.appendChild(userStoryElement);
			//userStoryArray
			JSONArray userStoryArray = object.getJSONArray("userStory");
			Element storyImagesElement = null;
			for (int i = 0; i < userStoryArray.length(); i++) {
				//初始化每行数据条数
				if (i == 0 || i % 3 == 0) {
					storyImagesElement = doc.createElement("storyImages");
					userStoryElement.appendChild(storyImagesElement);
				}
				JSONObject object2 = userStoryArray.getJSONObject(i);
				//storyImage-文章信息
				Element storyImageElement = doc.createElement("storyImage");
				storyImagesElement.appendChild(storyImageElement);
				//storyImage/imgUrl-图片信息
				JSONObject storyImageObject = object2.getJSONObject("storyImage");
				storyImageElement.setAttribute("imgUrl", storyImageObject.get("imgUrl").toString());
			}
		}
		return doc;
	}
	//	/**
	//	 * 呼叫 ../storyComment/.. 新增留言
	//	 *
	//	 * @param storyid
	//	 * @param whoid
	//	 * @param content
	//	 * @throws IOException
	//	 * @throws ParserConfigurationException
	//	 */
	//	public void storyComment(String storyid, String whoid, String content)
	//		throws IOException, ParserConfigurationException {
	//		HttpPut httpPut = new AuthHttpClient().bulidHttpPut("storyComment/");
	//		ArrayList<NameValuePair> pairList = new ArrayList();
	//		pairList.add(new BasicNameValuePair("story", storyid));
	//		pairList.add(new BasicNameValuePair("who", whoid));
	//		pairList.add(new BasicNameValuePair("content", content));
	//
	//		httpPut.setEntity(new UrlEncodedFormEntity(pairList, "UTF-8"));
	//
	//		CloseableHttpResponse response1 = HttpClients.createDefault().execute(httpPut);
	//		HttpEntity Entity = response1.getEntity();
	//		System.out.println(EntityUtils.toString(Entity));
	//	}

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
	public JSONArray getStoryComment(String storyId) throws ParserConfigurationException, IOException, TransformerConfigurationException, TransformerException {
		String stringUri = "stories/" + storyId + "/storyComment/";
		HttpGet httpGet = new AuthHttpClient().bulidHttpGet(stringUri);
		JSONArray jSONArrayOfstoryComments = new JSONArray();

		CloseableHttpResponse closeableHttpResponse = HttpClients.createDefault().execute(httpGet);
		try {
			HttpEntity httpEntity = closeableHttpResponse.getEntity();
			if (httpEntity != null) {
				String stringOfEntity = EntityUtils.toString(httpEntity, "UTF-8");
				JSONObject jSONObjectOfEntity = new JSONObject(stringOfEntity);
				String stringOfEmbedded = jSONObjectOfEntity.get("_embedded").toString();
				jSONArrayOfstoryComments = new JSONObject(stringOfEmbedded).getJSONArray("storyComments");
			}
		} finally {
			closeableHttpResponse.close();
		}
		return jSONArrayOfstoryComments;
	}

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
	public JSONObject findOneByThirdPartyId(String thirdParty, String userId) throws ClientProtocolException, IOException, URISyntaxException {
		String key = thirdParty + "Id";
		String url = "";
		switch (thirdParty) {
			case ("facebook"):
				url = "findOneByFacebookId";
				break;
			case ("google"):
				url = "findOneByGoogleId";
				break;
			default:
				url = "findOneByLineId";
				break;
		}

		ArrayList<NameValuePair> pairList = new ArrayList();
		pairList.add(new BasicNameValuePair(key, userId));

		URIBuilder builder = new URIBuilder(new AuthHttpClient().getHost() + "personnels/search/" + url);
		builder.setParameters(pairList);
		HttpGet httpGet = new AuthHttpClient().bulidHttpViaURI(builder.build());

		CloseableHttpResponse closeableHttpResponse = HttpClients.createDefault().execute(httpGet);
		HttpEntity httpEntity = closeableHttpResponse.getEntity();
		if (httpEntity == null) {
//			Logger.getGlobal().info("發生錯誤, Method: ApiService." + url);
			System.out.println("發生錯誤, Method: ApiService." + url + "()");
			return null;
		}

		JSONObject jSONObjectOfResult = null;
		String result = EntityUtils.toString(httpEntity, "UTF-8");

		if (result != null && result.length() > 0) {

			System.out.println("httpEntity: " + result);
			jSONObjectOfResult = new JSONObject(result);
			System.out.println("nickname: " + jSONObjectOfResult.get("nickname").toString());
		}

		return jSONObjectOfResult;
	}

	/**
	 * 呼叫 ../personnels/search/findOneByEmail 尋找帳號是否存在, 存在傳回 JSONObject;
	 * 反之回傳null
	 *
	 * @param email
	 * @return
	 * @throws URISyntaxException
	 * @throws IOException
	 */
	public JSONObject findOneByEmail(String email) throws URISyntaxException, IOException {
		ArrayList<NameValuePair> pairList = new ArrayList();
		pairList.add(new BasicNameValuePair("email", email));

		URIBuilder uRIBuilder = new URIBuilder(new AuthHttpClient().getHost() + "personnels/search/findOneByEmail");
		uRIBuilder.setParameters(pairList);
		HttpGet httpGet = new AuthHttpClient().bulidHttpViaURI(uRIBuilder.build());

		CloseableHttpResponse closeableHttpResponse = HttpClients.createDefault().execute(httpGet);
		HttpEntity httpEntity = closeableHttpResponse.getEntity();
		if (httpEntity == null) {
//			Logger.getGlobal().info("發生錯誤, Method: ApiService." + url);
			System.out.println("發生錯誤, Method: ApiService.findOneByEmail()");
			return null;
		}

		JSONObject jSONObjectOfResult = null;
		String result = EntityUtils.toString(httpEntity, "UTF-8");
		if (result != null && result.length() > 0) {

			System.out.println("httpEntity: " + result);
			jSONObjectOfResult = new JSONObject(result);
			System.out.println("nickname: " + jSONObjectOfResult.get("nickname").toString());
		}

		return jSONObjectOfResult;
	}

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
	public String registerUser(String nickname, String facebookId, String googleId, String lineId, String email, String lastname, String firstname, String birth, String gender, String storeName) throws ClientProtocolException, IOException {
		CloseableHttpClient closeableHttpClient = HttpClients.createDefault();
		HttpPost httpPost = new AuthHttpClient().bulidHttpPost("personnels");

		JSONObject jSONObjectOfParams = new JSONObject();
		jSONObjectOfParams.put("nickname", nickname);
		jSONObjectOfParams.put("facebookId", facebookId);
		jSONObjectOfParams.put("googleId", googleId);
		jSONObjectOfParams.put("lineId", lineId);
		jSONObjectOfParams.put("email", email);
		jSONObjectOfParams.put("lastname", lastname);
		jSONObjectOfParams.put("firstname", firstname);
		jSONObjectOfParams.put("birth", birth);
		jSONObjectOfParams.put("gender", gender);
		jSONObjectOfParams.put("storeName", storeName);
		System.out.println("jSONObjectOfParams: " + jSONObjectOfParams.toString());
		System.out.println("1");

		StringEntity stringEntityOfPersonnel = new StringEntity(jSONObjectOfParams.toString(), "UTF-8");
		System.out.println("stringEntityOfPersonnel: " + stringEntityOfPersonnel);
		System.out.println("2");
		httpPost.setEntity(stringEntityOfPersonnel);
		httpPost.setHeader("Content-type", "application/json");
		CloseableHttpResponse closeableHttpResponse = closeableHttpClient.execute(httpPost);
		System.out.println("3");

		closeableHttpResponse.close();
		closeableHttpClient.close();
		return "註冊成功";

	}

	/*
		  {
		 	"content": "this is a story content.",		 
		 	"imgUrls":{"URL","URL","URL"}
		    "Author": "http://localhost:8080/personnels/1" 
		  }
	 */
	public String postStory(String content, String personnelsUri, String[] imgUrls) throws Exception {
		CloseableHttpClient closeableHttpClient = HttpClients.createDefault();
		HttpPost httpPost = new AuthHttpClient().bulidHttpPost("stories");

		JSONObject jSONObjectOfParams = new JSONObject();
		jSONObjectOfParams.put("content", content);
//		jSONObjectOfParams.put("imgUrls", new JSONArray(Arrays.asList(imgUrls)));
		jSONObjectOfParams.put("author", "https://redan-api.herokuapp.com/personnels/" + personnelsUri);

		System.out.println("jSONObjectOfParams: " + jSONObjectOfParams.toString());

		StringEntity stringEntityOfPersonnel = new StringEntity(jSONObjectOfParams.toString(), "UTF-8");

		httpPost.setEntity(stringEntityOfPersonnel);
		httpPost.setHeader("Content-type", "application/hal+json;charset=UTF-8");
		CloseableHttpResponse closeableHttpResponse = closeableHttpClient.execute(httpPost);

		System.out.println("----------------------------------------");
		System.out.println(closeableHttpResponse.getStatusLine());

		JSONObject storyInfo = new JSONObject(
			EntityUtils.toString(closeableHttpResponse.getEntity()));
		String storyUrl = storyInfo.getJSONObject("_links").getJSONObject("self").getString("href");

		Arrays.asList(imgUrls).forEach(imgUrl -> {
			try {
				System.out.println(postImgUrl(imgUrl, null, storyUrl));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		});

		closeableHttpResponse.close();
		closeableHttpClient.close();
		return "";

	}

	/*	
		{
			"story":"http://localhost:8080/stories/1",
			"who":"http://localhost:8080/personnels/1",
			"content":"oka"
		}
	 */
	public String postComments(String content, String personnelsUri, String storyUri) throws ClientProtocolException, IOException {
		CloseableHttpClient closeableHttpClient = HttpClients.createDefault();
		HttpPost httpPost = new AuthHttpClient().bulidHttpPost("storyComments");

		JSONObject jSONObjectOfParams = new JSONObject();
		jSONObjectOfParams.put("story", storyUri);
		jSONObjectOfParams.put("who", personnelsUri);
		jSONObjectOfParams.put("content", content);

		System.out.println("jSONObjectOfParams: " + jSONObjectOfParams.toString());

		StringEntity stringEntityOfPersonnel = new StringEntity(jSONObjectOfParams.toString(), "UTF-8");

		httpPost.setEntity(stringEntityOfPersonnel);
		httpPost.setHeader("Content-type", "application/json");
		CloseableHttpResponse closeableHttpResponse = closeableHttpClient.execute(httpPost);

		closeableHttpResponse.close();
		closeableHttpClient.close();
		return "留言成功";
	}

	/*
	{	
		"url":"http://localhost:8080/img1",
		"content":"oka",
		"story":"http://localhost:8080/stories/1"
	}
	 */
	public String postImgUrl(String imgUrl, String content, String storyUrl) throws ClientProtocolException, IOException {
		CloseableHttpClient closeableHttpClient = HttpClients.createDefault();
		HttpPost httpPost = new AuthHttpClient().bulidHttpPost("storyImages");

		JSONObject jSONObjectOfParams = new JSONObject();
		jSONObjectOfParams.put("url", imgUrl);
		jSONObjectOfParams.put("content", "redan");
		jSONObjectOfParams.put("story", storyUrl);

		System.out.println("postImgUrl: " + jSONObjectOfParams.toString());

		StringEntity stringEntityOfPersonnel = new StringEntity(jSONObjectOfParams.toString(), "UTF-8");

		httpPost.setEntity(stringEntityOfPersonnel);
		httpPost.setHeader("Content-type", "application/hal+json;charset=UTF-8");
		CloseableHttpResponse closeableHttpResponse = closeableHttpClient.execute(httpPost);
		System.out.println(EntityUtils.toString(closeableHttpResponse.getEntity()));
		closeableHttpResponse.close();
		closeableHttpClient.close();
		return "上傳成功";
	}
		/**
	 * 访问个人主页
	 *
	 * @param id
	 * @return
	 * @throws TransformerConfigurationException
	 * @throws TransformerException
	 * @throws IOException
	 * @throws ParserConfigurationException
	 */
	public Document getHomepage(Integer id) throws TransformerConfigurationException, TransformerException, IOException, ParserConfigurationException {
		Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
		Element documentElement = doc.createElement("document");
		doc.appendChild(documentElement);
		CloseableHttpResponse response1 = HttpClients.createDefault().execute(new HttpGet("https://redan-api.herokuapp.com/personnels/search/findOneById?id=" + id));
		HttpEntity entity = response1.getEntity();
		try {
			if (null != entity) {
				String getDataStr = EntityUtils.toString(entity, "UTF-8");
				JSONObject jsonObjectDataStr = new JSONObject(getDataStr);

				//创建nickname
				Element nicknameElement = doc.createElement("nickname");
				String nicknameString = jsonObjectDataStr.get("nickname").toString();
				nicknameElement.appendChild(doc.createTextNode(nicknameString));
				documentElement.appendChild(nicknameElement);

				//创建followingCount
				Element followingCountElement = doc.createElement("followingCount");
				String followingCountString = jsonObjectDataStr.get("followingCount").toString();
				followingCountElement.appendChild(doc.createTextNode(followingCountString));
				documentElement.appendChild(followingCountElement);

				//创建followerCount
				Element followerCountElement = doc.createElement("followerCount");
				String followerCountString = jsonObjectDataStr.get("followerCount").toString();
				followerCountElement.appendChild(doc.createTextNode(followerCountString));
				documentElement.appendChild(followerCountElement);

				//创建userStoryCount
				Element userStoryCountElement = doc.createElement("userStoryCount");
				String userStoryCountString = jsonObjectDataStr.get("userStoryCount").toString();
				userStoryCountElement.appendChild(doc.createTextNode(userStoryCountString));
				documentElement.appendChild(userStoryCountElement);

				//创建coverImgUrl
				Element coverImgUrlElement = doc.createElement("coverImgUrl");
				String coverImgUrlString = jsonObjectDataStr.get("coverImgUrl").toString();
				coverImgUrlElement.setAttribute("cover", coverImgUrlString);
				documentElement.appendChild(coverImgUrlElement);

				//创建profileImgUrl
				Element profileImgUrlElement = doc.createElement("profileImgUrl");
				String profileImgUrlString = jsonObjectDataStr.get("profileImgUrl").toString();
				profileImgUrlElement.setAttribute("cover", profileImgUrlString);
				documentElement.appendChild(profileImgUrlElement);

				//创建profileText
				Element profileTextElement = doc.createElement("profileText");
				profileTextElement.appendChild(doc.createTextNode(jsonObjectDataStr.get("profileText").toString()));
				documentElement.appendChild(profileTextElement);

				//创建cuserStory  第一层
				JSONArray jsonArrayUserStorys = jsonObjectDataStr.getJSONArray("userStory");

				Element userStoryElement = doc.createElement("userStorys");

				for (int i = 0; i < jsonArrayUserStorys.length(); i++) {
					Element userElement = doc.createElement("userStory");
					JSONObject jsonObjectUserStory = jsonArrayUserStorys.getJSONObject(i);
					System.out.println("jsonObjectUserStory\t" + jsonObjectUserStory);

					//创建storyImage  第二层
					JSONObject jsonObjectStoryImage = jsonObjectUserStory.getJSONObject("storyImage");
					Element storyImageElement = doc.createElement("storyImage");
					userElement.appendChild(storyImageElement);

					//创建 imgUrl 第三层
					String imgUrlString = jsonObjectStoryImage.get("imgUrl").toString();
					Element imgUrlElement = doc.createElement("imgUrl");
					imgUrlElement.setAttribute("att", imgUrlString);
					storyImageElement.appendChild(imgUrlElement);

					userElement.appendChild(storyImageElement);
					userStoryElement.appendChild(userElement);
				}
				documentElement.appendChild(userStoryElement);

			}
		} finally {
			response1.close();
		}

		DOMSource domSource = new DOMSource(doc);
		StringWriter writer = new StringWriter();
		StreamResult result = new StreamResult(writer);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		transformer.transform(domSource, result);
		System.out.println(writer.toString());
		return doc;
	}

	/**
	 * 返回根据评论者id找头像
	 *
	 * @param id
	 * @return
	 * @throws java.io.IOException
	 */
	public String getImg(Integer id) throws IOException {
		String str = null;
		CloseableHttpResponse response1 = HttpClients.createDefault().execute(new HttpGet("https://redan-api.herokuapp.com/personnels/search/findOneById?id=" + id));
		HttpEntity entity = response1.getEntity();
		if (null != entity) {
			String getDataStr = EntityUtils.toString(entity, "UTF-8");
			System.out.println("getDataStr\t" + getDataStr);
			JSONObject jsonObjectDataStr = new JSONObject(getDataStr);
			String profileImgUrlValue = jsonObjectDataStr.get("profileImgUrl").toString();
			str = profileImgUrlValue;
		}
		System.out.println("APIservice \t" + str);
		return str;
	}
}
