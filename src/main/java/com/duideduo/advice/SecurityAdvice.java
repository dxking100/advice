package com.duideduo.advice;

import com.duideduo.aes.AESUtil;
import com.duideduo.security.SecurityUtil;
import com.duideduo.token.TokenUtil;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

@Aspect
@Component
public class SecurityAdvice {

    @Before("@annotation(com.ttd.advice.TTDUserInfo)")
    public void beforce(JoinPoint jp) throws Throwable {
        HttpServletRequest request =((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String walletToken =  request.getHeader("walletToken");
        String shopToken =  request.getHeader("shopToken");
        String roundShopToken =  request.getHeader("roundShopToken");
        String chatToken =  request.getHeader("chatToken");

        if(walletToken != null){
            request.setAttribute("walletUserInfo", AESUtil.decode(walletToken.getBytes(), TokenUtil.WALLET_AES_KEY));
        }if(shopToken != null){
            request.setAttribute("shopUserInfo", AESUtil.decode(shopToken.getBytes(), TokenUtil.SHOP_AES_KEY));
        }if(roundShopToken != null){
            request.setAttribute("roundShopUserInfo", AESUtil.decode(roundShopToken.getBytes(), TokenUtil.ROUND_SHOP_AES_KEY));
        }if(chatToken != null){
            request.setAttribute("chatUserInfo", AESUtil.decode(chatToken.getBytes(), TokenUtil.CHAT_AES_KEY));
        }
    }

    @Around("@annotation(com.ttd.advice.TTDSecurity)")
    public String around( ProceedingJoinPoint point) throws Throwable {
        HttpServletRequest request =((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String clientParam = request.getParameter("sCondiction");
        clientParam = clientParam.replaceAll("\r\n","");
        if(clientParam == null){
            throw new Exception("sCondiction 加密参数为空");
        }
        String[] paramString =  SecurityUtil.serverDecode(clientParam);
        request.setAttribute("param",paramString[0]);
        String ret = (String)point.proceed();
        return SecurityUtil.serverEncode(ret,paramString[1]);

    }

}