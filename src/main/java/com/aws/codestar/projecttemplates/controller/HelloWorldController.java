package com.aws.codestar.projecttemplates.controller;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.stream.StreamSource;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import com.aws.codestar.projecttemplates.configuration.oauth2Component.ThirdPartyAuthentication;
import com.aws.codestar.projecttemplates.configuration.securityComponent.IAuthenticationFacade;
import com.aws.codestar.projecttemplates.model.Account;
import com.aws.codestar.projecttemplates.model.Emotion;
import com.aws.codestar.projecttemplates.model.Story;
import com.aws.codestar.projecttemplates.service.ApiService;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.transform.TransformerException;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Basic Spring MVC controller that handles all GET requests.
 */
@RestController
@RequestMapping("/")
public class HelloWorldController {

	@Autowired
	private ApiService apiService;

	@Autowired
	private ThirdPartyAuthentication thirdPartyAuthentication;

	/**
	 * 访问个人主页
	 *
	 * @param id
	 * @return
	 * @throws Exception
	 */
	@RequestMapping(value = "/Personalpage")
	public ModelAndView getPersonalpage(@RequestParam(value = "id", required = true, defaultValue = "3") Integer id) throws Exception {

		ModelAndView model = new ModelAndView("Personalpage");
		model.addObject("xmlSource", apiService.getHomepage(id));
		System.out.println("id\t" + id);
		return model;
	}

	/**
	 * 传前台图片的路径字符串
	 *
	 * @param id
	 * @return
	 * @throws IOException
	 */
	@RequestMapping(value = "/img")
	public String getString(@RequestParam(value = "id", required = true) Integer id) throws IOException {
		System.out.println("id\t" + id);
		return apiService.getImg(id);
	}

	/**
	 * 導向登入後頁面
	 *
	 * @param response
	 * @param httpSession
	 * @param code 可為空, 以Line API 登入時傳入Line.code
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws TransformerException
	 * @throws URISyntaxException
	 */
	@RequestMapping(value = "/")
	public ModelAndView index(HttpServletResponse response, HttpSession httpSession,
		@RequestParam(required = false) String code)
		throws IOException, ParserConfigurationException, TransformerException, URISyntaxException {
		JSONObject jSONObject = null;

		// 取得 Line Token, 並解析資料以得 email 資訊
		if (code != null) {
			// thirdParty = "line";
			jSONObject = thirdPartyAuthentication.getToken(code);

			if (jSONObject != null) {
				String profile = jSONObject.getString("profile");
				System.out.println("get email from Line: " + jSONObject.getString("email"));
//				String userName = find(httpSession, "line", new JSONObject(profile).getString("userId"), "");
//				System.out.println("get userName from Line: " + userName);
			} else {
				return null;
			}
		}

		if (httpSession.getAttribute("requestURI") != null) {
			// response.sendRedirect(httpSession.getAttribute("requestURI").toString());
		}
		ModelAndView model = new ModelAndView("index");
		model.addObject("xmlSource", apiService.getStory(httpSession));
		return model;
	}

	/**
	 * 呼叫 apiService.findOneBythirdParty(),判斷登入帳號是否存在,存在就設定session.attribute
	 *
	 * @param httpSession
	 * @param thirdParty 第三方登入API
	 * @param userId 第三方供應商提供之使用者ID
	 * @param userEmail 可為空, 有值表示為BBMall會員
	 * @throws IOException
	 * @throws URISyntaxException
	 */
	private void getId(HttpSession httpSession, String thirdParty, String userId, String userEmail)
		throws IOException, URISyntaxException {
		JSONObject jSONObject = null;

		if (userEmail != null && userEmail.length() > 0) {
			jSONObject = apiService.findOneByEmail(userEmail);
		} else {
			jSONObject = apiService.findOneByThirdPartyId(thirdParty, userId);
		}

		if (jSONObject != null) {
			String uuid = jSONObject.get("universallyUniqueIdentifier").toString();
			String personnelId = jSONObject.get("id").toString();
			String nickname = jSONObject.get("nickname").toString();
			String email = jSONObject.get("email").toString();
			String personnelHref = jSONObject.getJSONObject("_links").getJSONObject("self").get("href").toString();

			httpSession.setAttribute("me", uuid);
			httpSession.setAttribute("id", personnelId);
			httpSession.setAttribute("personnelHref", personnelHref);
			httpSession.setAttribute("thirdParty", thirdParty);
			httpSession.setAttribute("nickname", nickname);
			httpSession.setAttribute("email", email);
		}
	}

	/**
	 * 註冊頁面
	 *
	 * @param request
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 */
	@RequestMapping(value = "/registerview")
	public ModelAndView registerview(HttpServletRequest request) throws IOException, ParserConfigurationException {

		// builds absolute path of the XML file
		String xmlFile = "resources/xml.xml";
		String contextPath = request.getServletContext().getRealPath("");
		String xmlFilePath = contextPath + File.separator + xmlFile;
		Source source = new StreamSource(new File(xmlFilePath));

		ModelAndView model = new ModelAndView("register");
		model.addObject("xmlSource", source);
		return model;
	}

	/**
	 * 註冊動作, call apiService.registerUser() 新增帳號資料
	 *
	 * @param account
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 */
	@RequestMapping(value = "/register", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE) // ,
	// produces
	// =
	// MediaType.APPLICATION_JSON_UTF8_VALUE
	public String register(Account account) throws IOException, ParserConfigurationException {
		// System.out.println("firstName:" + account.getFirstName());
		// System.out.println("lastName:" + account.getLastName());
		// System.out.println("email:" + account.getEmail());
		// System.out.println("password:" + account.getPassword());
		// System.out.println("confirmpassword:" + account.getConfirmPassword());
		return apiService.registerUser(account.getFirstName(), "", "", "", account.getEmail(), account.getLastName(),
			account.getFirstName(), "", "", "");
	}

	/**
	 * 帳號登入頁面
	 *
	 * @param request
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 */
	@RequestMapping(value = "/login")
	public ModelAndView login(HttpServletRequest request) throws IOException, ParserConfigurationException {
		String xmlFile = "resources/xml.xml";
		String contextPath = request.getServletContext().getRealPath("");
		String xmlFilePath = contextPath + File.separator + xmlFile;
		Source source = new StreamSource(new File(xmlFilePath));

		ModelAndView model = new ModelAndView("login");
		model.addObject("xmlSource", source);
		return model;
	}

	/**
	 * 登出動作, 移除session.attrbute並回到首頁
	 *
	 * @param response
	 * @param httpSession
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws TransformerException
	 * @throws URISyntaxException
	 */
	@RequestMapping(value = "/logout")
	public ModelAndView logout(HttpServletResponse response, HttpSession httpSession)
		throws IOException, ParserConfigurationException, TransformerException, URISyntaxException {
		httpSession.removeAttribute("me");
		httpSession.removeAttribute("thirdParty");
		httpSession.removeAttribute("nickname");
		httpSession.removeAttribute("email");
		return index(response, httpSession, null);
	}

	@RequestMapping(value = "/memberCenter", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public ModelAndView memberCenter(HttpServletRequest request, HttpServletResponse response, HttpSession httpSession)
		throws IOException, ParserConfigurationException, TransformerException, URISyntaxException {
		if (httpSession.getAttribute("me") == null) {
			System.out.println("getRequestURI: " + request.getRequestURI());
			httpSession.setAttribute("requestURI", request.getRequestURI());
			return login(request);
		}

		String xmlFile = "resources/xml.xml";
		String contextPath = request.getServletContext().getRealPath("");
		String xmlFilePath = contextPath + File.separator + xmlFile;
		Source source = new StreamSource(new File(xmlFilePath));

		ModelAndView model = new ModelAndView("memberCenter");
		model.addObject("xmlSource", source);

		return model;
	}

	/**
	 * 導向 Line 登入驗證
	 *
	 * @return Line 登入驗證 URL
	 */
	@RequestMapping(value = "/line")
	public String lineHref() {
		return "https://access.line.me/oauth2/v2.1/authorize?response_type=code" + "&client_id="
			+ System.getenv("LINE_CLIENT_ID") + "&redirect_uri=" + System.getenv("LINE_REDIRECT_URI") + "&state="
			+ getRandomString() + "&scope=" + "openid%20profile%20email" + "&nonce=" + getRandomString();
	}

	/**
	 * 產生隨機字串
	 *
	 * @return 隨機字串
	 */
	public String getRandomString() {
		SecureRandom RANDOM = new SecureRandom();
		byte[] bytes = new byte[32];
		RANDOM.nextBytes(bytes);

		return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/**
	 * 搜尋帳號是否存在(Facebook, Google, Line)
	 *
	 * @param httpSession
	 * @param thirdParty 第三方登入API
	 * @param userId 第三方供應商提供之使用者ID
	 * @param userEmail 可為空, 有值表示為BBMall會員
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws URISyntaxException
	 */
//	@RequestMapping(value = "/find", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
//	public String find(HttpSession httpSession, @RequestParam(required = false) String thirdParty,
//		@RequestParam(required = false) String userId, @RequestParam(required = false) String userEmail)
//		throws IOException, ParserConfigurationException, URISyntaxException {
//		JSONObject jSONObject = null;
//		getId(httpSession, thirdParty, userId, userEmail);
//
//		if (userEmail != null && userEmail.length() > 0) {
//			jSONObject = apiService.findOneByEmail(userEmail);
//		} else {
//			jSONObject = apiService.findOneByThirdPartyId(thirdParty, userId);
//		}
//		if (jSONObject == null) {
//			return "沒有這個帳號哦！";
//		}
//
//		return jSONObject.getString("nickname");
//	}
	/**
	 * 留言
	 *
	 * @param story
	 * @param httpSession
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 */
	@PreAuthorize("hasRole('ROLE_USER')")
	@RequestMapping(value = "/postComment", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public String postComment(Story story, HttpSession httpSession)
		throws IOException, ParserConfigurationException, TransformerException {

		System.out.println(apiService.postComments(story.getContent(), story.getWho(), story.getStoryHref()));

		JSONArray jSONArrayComment = apiService.getStoryComment(story.getStoryId());
		JSONArray jSONArray = new JSONArray();

		for (int i = 0; i < jSONArrayComment.length(); i++) {
			JSONObject jSONObject = new JSONObject();
			jSONObject.put("who", jSONArrayComment.getJSONObject(i).get("who").toString());
			jSONObject.put("whoId", jSONArrayComment.getJSONObject(i).get("whoId").toString());
			jSONObject.put("img", apiService.getImg(Integer.parseInt(jSONArrayComment.getJSONObject(i).get("whoId").toString())));
			jSONObject.put("content", jSONArrayComment.getJSONObject(i).get("content").toString());
			jSONArray.put(jSONObject);
		}

		System.out.println("jSONArray: " + jSONArray);
		return jSONArray.toString();
	}

	/**
	 * 按讚
	 *
	 * @param emotion
	 * @param httpSession
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 */
	@PreAuthorize("hasRole('ROLE_USER')")
	@RequestMapping(value = "/like", method = RequestMethod.POST)
	public String like(Emotion emotion, HttpSession httpSession) throws IOException, ParserConfigurationException {

		System.out.println("story:" + emotion.getStory());
		System.out.println("who:" + emotion.getWho());
		return emotion.toString();
	}

	/**
	 * 收藏
	 *
	 * @param emotion
	 * @param httpSession
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 */
	@PreAuthorize("hasRole('ROLE_USER')")
	@RequestMapping(value = "/bookmark", method = RequestMethod.POST)
	public String bookmark(Emotion emotion, HttpSession httpSession) throws IOException, ParserConfigurationException {

		System.out.println("story:" + emotion.getStory());
		System.out.println("who:" + emotion.getWho());
		return emotion.toString();
	}

	/**
	 * 發文
	 *
	 * @param imgUrls
	 * @param who
	 * @param storyContent
	 * @param storyHref
	 * @param request
	 * @param httpSession
	 * @return
	 * @throws Exception
	 */
	@PreAuthorize("hasRole('ROLE_USER')")
	@RequestMapping(value = "/postStory", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public String postStory(
		@RequestParam(required = false) String imgUrls,
		@RequestParam(required = false) String who,
		@RequestParam(required = false) String storyContent,
		HttpSession httpSession) throws Exception {
		JSONObject jSONObject = new JSONObject(imgUrls);

		System.out.println("jSONObject = " + jSONObject.toString());

		JSONArray jSONArray = jSONObject.getJSONArray("urls");
		String[] stringsOfImgUrls = new String[jSONArray.length()];

		for (int i = 0; i < jSONArray.length(); i++) {
			stringsOfImgUrls[i] = jSONArray.getJSONObject(i).get("url").toString();
		}
		apiService.postStory(storyContent, who, stringsOfImgUrls);

		return "發文成功";
	}

	@PreAuthorize("hasRole('ROLE_USER')")
	@RequestMapping(value = "/postImgUrl", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
	public String postImgUrl(@RequestParam(required = false) String url, @RequestParam(required = false) String content, String storyUrl, HttpSession httpSession) throws IOException {
		System.out.println("url: " + url);
		System.out.println("content: " + content);
		System.out.println(apiService.postImgUrl(url, content, ""));
		return "圖片上傳成功";
	}

	/**
	 * 个人主页
	 *
	 */
	@RequestMapping(value = "/memberCenter", method = RequestMethod.GET, produces = MediaType.TEXT_HTML_VALUE)
	public ModelAndView getPersonal2(String id, HttpServletResponse response) throws ParserConfigurationException, IOException, TransformerConfigurationException, TransformerException {

		// 将XML源文件添加到模型中，以便XsltView能够检测
		ModelAndView model = new ModelAndView("memberCenter");
		model.addObject("xmlSource", apiService.getPersonnels(id));
		return model;

	}
}
