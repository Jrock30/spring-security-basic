package com.jrock.springsecuritybasic.security.common;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * 사용자가 전달하는 추가적인 파라메타를 저장하는 클래스
 */
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    public String getSecretKey() {
        return secretKey;
    }

    private String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key");
    }
}
