package com.aws.codestar.projecttemplates.configuration.oauth2Component;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpSession;
import javax.xml.parsers.ParserConfigurationException;

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
import org.json.JSONObject;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Component
public class ThirdPartyAuthentication {

	/**
	 * 取得 Line Token
	 *
	 * @param code
	 * @return
	 * @throws IOException
	 * @throws ParserConfigurationException
	 */
	public JSONObject getToken(String code) throws IOException, ParserConfigurationException {
		JSONObject jSONObject = new JSONObject();

		// 建立 CloseableHttpClient & HttpPost
		CloseableHttpClient closeableHttpClient = HttpClients.createDefault();

		// 取得 access token
		HttpPost httpPost = new HttpPost("https://api.line.me/oauth2/v2.1/token");

		// 設定 Request parameters and other properties.
		// 取得 access_token 所需參數如下:
		// 參數值為 https://developers.line.biz/console/channel/... 設定之內容
		// 108.03.04 以下設定為系統參數(tomcat setenv.bat)
		List<NameValuePair> params = new ArrayList<>(2);
		params.add(new BasicNameValuePair("grant_type", System.getenv("LINE_GRANT_TYPE")));
		params.add(new BasicNameValuePair("code", code));
		params.add(new BasicNameValuePair("redirect_uri", System.getenv("LINE_REDIRECT_URI")));
		params.add(new BasicNameValuePair("client_id", System.getenv("LINE_CLIENT_ID")));
		params.add(new BasicNameValuePair("client_secret", System.getenv("LINE_CLIENT_SECRET")));
		httpPost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
		httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");

		// Execute and get the response.
		CloseableHttpResponse closeableHttpResponseOfToken = closeableHttpClient.execute(httpPost);
		HttpEntity httpEntityOfToken = closeableHttpResponseOfToken.getEntity();

		String stringToken = "";

		System.out.println("token--getStatusLine: " + closeableHttpResponseOfToken.getStatusLine());
		if (closeableHttpResponseOfToken.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
			if (httpEntityOfToken != null) {
				stringToken = EntityUtils.toString(httpEntityOfToken, "UTF-8");
				System.out.println("token: " + stringToken);
			} else {
				jSONObject.put("errorMessage", "ERROR! closeableHttpResponseOfToken.getEntity() = null");
				return jSONObject;
			}
		} else {
			System.out.println("token--ERROR");
			jSONObject.put("errorMessage", "ERROR! closeableHttpResponseOfToken.getStatusLine() = "
				+ closeableHttpResponseOfToken.getStatusLine());
			return jSONObject;
		}

		System.out.println("token--httppost: " + httpPost.toString());

		JSONObject jsonObjectOfToken = new JSONObject(stringToken);
		System.out.println("token--finished");
		closeableHttpResponseOfToken.close();

		String[] jwtArray = decodeJWT(jsonObjectOfToken.get("id_token").toString(), "Line");
		if (jwtArray == null) {
			System.out.println("decodeJWT Error!--getToken");
			jSONObject.put("errorMessage", "ERROR! decode JWT failed");
			return jSONObject;
		} else {
			JSONObject jsonObjectJWT = new JSONObject(jwtArray[1]);
			System.out.println("jsonObjectJWT: " + jsonObjectJWT.toString());
			System.out.println("JWTemail: " + jsonObjectJWT.getString("email"));
			System.out.println(Arrays.toString(jwtArray));
			jSONObject.put("email", jsonObjectJWT.getString("email"));
		}

		// 取得 user profiles
		HttpGet httpGet = new HttpGet("https://api.line.me/v2/profile");

		// 設定 Authorization
		httpGet.setHeader("Authorization", "Bearer " + jsonObjectOfToken.get("access_token").toString());

		CloseableHttpResponse closehttpResponseOfProfile = closeableHttpClient.execute(httpGet);
		HttpEntity httpEntityOfProfile = closehttpResponseOfProfile.getEntity();

		String stringProfile = "";

		System.out.println("profile--getStatusLine: " + closehttpResponseOfProfile.getStatusLine());
		if (closehttpResponseOfProfile.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
			if (httpEntityOfProfile != null) {
				stringProfile = EntityUtils.toString(httpEntityOfProfile, "UTF-8");

				JSONObject jsonObjectProfile = new JSONObject(stringProfile);

				System.out.println("profile: " + stringProfile);
				System.out.println("--------------------------");
				System.out.println("userId: " + jsonObjectProfile.getString("userId"));
				System.out.println("displayName: " + jsonObjectProfile.getString("displayName"));
				System.out.println("pictureUrl: " + jsonObjectProfile.getString("pictureUrl"));
				System.out.println("statusMessage: " + jsonObjectProfile.getString("statusMessage"));
				System.out.println("--------------------------");

				jSONObject.put("profile", stringProfile);
			} else {
				jSONObject.put("errorMessage", "ERROR! closehttpResponseOfProfile.getEntity() = null");
				return jSONObject;
			}
		} else {
			System.out.println("profile--ERROR");
			jSONObject.put("errorMessage", "ERROR! closehttpResponseOfProfile.getStatusLine() = "
				+ closehttpResponseOfProfile.getStatusLine());
			return jSONObject;
		}
		System.out.println("profile--httppost: " + httpGet.toString());
		return jSONObject;
	}

	/**
	 * Json Web Token 轉譯
	 *
	 * @param idtoken 要轉譯的 JWT
	 * @param thirdParty公司
	 * @return 傳回一陣列, JWT經轉譯後的內容, 格式為{header, body, signature}
	 */
	private String[] decodeJWT(String idtoken, String thirdParty) throws UnsupportedEncodingException {

		String jwtToken = idtoken;
		if (jwtToken == null) {
			return null;
		}
		System.out.println("------------- idtoken --------------");
		System.out.println("(" + thirdParty + ")" + jwtToken);
		System.out.println("------------------------------------");

		System.out.println("------------ Decode JWT ------------");

		String[] jwtTokenArray = jwtToken.split("\\.");
		String base64EncodedHeader = jwtTokenArray[0];
		String base64EncodedBody = jwtTokenArray[1];
		String base64EncodedSignature = jwtTokenArray[2];

		Base64 base64Url = new Base64(true);
		String header = new String(base64Url.decode(base64EncodedHeader), "UTF-8");
		System.out.println("(" + thirdParty + ") JWT Header : " + header);

		String body = new String(base64Url.decode(base64EncodedBody), "UTF-8");
		System.out.println("(" + thirdParty + ") JWT Body : " + body);
		System.out.println("(" + thirdParty + ") JWT Body.sub : " + new JSONObject(body).get("sub").toString());

		String signature = new String(base64Url.decode(base64EncodedSignature), "UTF-8");
		System.out.println("(" + thirdParty + ") JWT Signature : " + signature);

		System.out.println("---------------- 完成 ---------------");
		String[] result = {header, body, signature};

		// final Base64 base64 = new Base64();
		// final String text = "字串文字";
		// final byte[] textByte = text.getBytes("UTF-8");
		// //編碼
		// final String encodedText = base64.encodeToString(textByte);
		// System.out.println("字串文字-編碼: " + encodedText);
		// //解碼
		// System.out.println("字串文字-解碼: " + new String(base64.decode(encodedText),
		// "UTF-8"));
		return result;
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
}
