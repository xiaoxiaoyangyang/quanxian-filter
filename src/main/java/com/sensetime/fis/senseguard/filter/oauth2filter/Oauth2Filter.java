package com.sensetime.fis.senseguard.filter.oauth2filter;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sensetime.fis.senseguard.filter.vo.CheckPermissionParam;

/**
 * @author guozhiyang_vendor
 */
@WebFilter(urlPatterns = "/*", filterName = "oauth2filter")
public class Oauth2Filter implements Filter {
	private static Logger logger = LoggerFactory.getLogger(Oauth2Filter.class);
	private static final String OPTIONS="OPTIONS";
	@Autowired
	@Qualifier(value = "ret")
	private RestTemplate ret;
	@Autowired
	private HttpServletRequest request;

	@Value("${senseguard.oauth2.whitelist}")
	private String whiteList;

	@Value("${senseguard.oauth2.checkPermission:}")
	private String permissionCheckUrl;

	@Value("${senseguard.oauth2.hostPattern:}")
	private String hostPattern;

	private ObjectMapper objectMapper = new ObjectMapper();


	@Override
	public void init(FilterConfig filterConfig) throws ServletException {}
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		String uri = httpServletRequest.getRequestURI();
		String path = uri.replaceAll(httpServletRequest.getContextPath(), "");
		// 过滤白名单
		Set<String> collect = Arrays.stream(whiteList.split(",")).map(String::trim).collect(Collectors.toSet());
		//比中b false 未必中true
		AntPathMatcher antPathMatcher = new AntPathMatcher();
		boolean b = collect.stream().noneMatch(s -> antPathMatcher.match(s, path));
		logger.info("path-------------路径"+path);
		if (!b) {
			logger.info("白名单匹配日结果为true--------------->放行了");
			chain.doFilter(request, response);
		} else {
			String method = httpServletRequest.getMethod();
			if (method.equalsIgnoreCase(OPTIONS)) {
				chain.doFilter(request, response);
			} else {
				logger.info("----------------------------Header----------------------------");
				Pattern pattern = Pattern.compile(hostPattern);
				String host = httpServletRequest.getHeader("host");
				boolean isMatch = pattern.matcher(host).matches();
				logger.info("host: " + host + " ,pattern: " + pattern + ", isMatcher: " + isMatch);
				// 内部访问，不校验权限
				if (isMatch) {
					chain.doFilter(request, response);
				}else{
					logger.info("filter current uri=[ " + uri + " ] ,path=[ " + path + " ]");
					String accessToken = httpServletRequest.getHeader("accessToken");
					Integer isPermission = 0;
					if (StringUtils.isEmpty(accessToken)) {
						printErrorResult(response, uri, response.getOutputStream(),isPermission);
					} else {

						CheckPermissionParam checkPermissionParam = new CheckPermissionParam();
						checkPermissionParam.setUri(path);
						checkPermissionParam.setAccessToken(accessToken);
						checkPermissionParam.setAction(method);

						HttpHeaders headers = new HttpHeaders();
						headers.setContentType(MediaType.APPLICATION_JSON);
						HttpEntity<CheckPermissionParam> httpEntity = new HttpEntity<>(checkPermissionParam, headers);

						logger.info("permissionCheckUrl: " + permissionCheckUrl + " ,httpEntity: "
								+ JSONObject.toJSON(httpEntity));
						try {
							ResponseEntity<Integer> responseEntity = ret.exchange(permissionCheckUrl,
									HttpMethod.POST, httpEntity, Integer.class);
							isPermission = responseEntity.getBody();
						} catch (Exception e) {
							logger.error(e.getMessage());
							printErrorResult(response, uri, response.getOutputStream(),isPermission);
						}
						if (isPermission == 1) {
							chain.doFilter(request, response);
						}else if
								(isPermission == 2 || isPermission == 3){
							printErrorResult(response, uri, response.getOutputStream(),isPermission);
						}else if
								(isPermission == 4){
							printErrorResult(response, uri, response.getOutputStream(),isPermission);
						}
						logger.info("filter current path=[ " + path + " ] , is permission ? =[ " + isPermission + " ]");
					}
				}
			}
		}
	}

	/**
	 * 打印错误结果
	 * @param response
	 * @param uri
	 * @param writer
	 * @param isPermission
	 * @throws IOException
	 * @throws JsonProcessingException
	 */
	private void printErrorResult(ServletResponse response, String uri, OutputStream writer, Integer isPermission)
			throws IOException, JsonProcessingException {
		HttpServletResponse res = (HttpServletResponse) response;
		res.setCharacterEncoding("UTF-8");
		res.setContentType("application/json;charset=UTF-8");
		res.setStatus(HttpStatus.UNAUTHORIZED.value());
		String s = errorResult(uri, isPermission);
		writer.write(s.getBytes("UTF-8"));
		writer.flush();
		writer.close();
	}

	/**
	 * 封装的错误消息
	 * @param uri
	 * @param isPermission
	 * @return
	 * @throws JsonProcessingException
	 */
	private String errorResult(String uri ,Integer isPermission) throws JsonProcessingException {
		int i=0;
		int j=2;
		int m=3;
		int n=4;
		String result = "";
		if (isPermission == j || isPermission == m ||isPermission==i){
			Map<String, String> resultMap = new HashMap<>(16);
			resultMap.put("code", "401014");
			resultMap.put("message", "无相关的权限");
			resultMap.put("path", uri);
			resultMap.put("method",request.getMethod());
			result = objectMapper.writeValueAsString(resultMap);
			return result;
		}
		if (isPermission == n){
			Map<String, String> resultMap = new HashMap<>(16);
			resultMap.put("code", "401015");
			resultMap.put("message", "TOKEN到期");
			resultMap.put("path", uri);
			resultMap.put("method", request.getMethod());
			result= objectMapper.writeValueAsString(resultMap);
			return result;
		}
		return result;
	}
	@Override
	public void destroy() {}

}
