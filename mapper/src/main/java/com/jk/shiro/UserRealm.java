package com.jk.shiro;


import com.jk.entity.User;
import com.jk.mapper.LoginMapper;
import com.jk.util.EncryptUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;

public class UserRealm extends AuthorizingRealm {

    @Autowired
    private LoginMapper loginMapper;

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

         //获取基于用户名和密码的令牌
        //实际上这个authcToken是从LoginController里面currentUser.login(token)传过来的
        Subject currentUser = SecurityUtils.getSubject();
        Session session = currentUser.getSession();

        UsernamePasswordToken tokentwo = (UsernamePasswordToken)token;

        String code = (String)session.getAttribute("rand");
        String host = tokentwo.getHost();

        if(!code.equals(host))
        {
            throw new AuthenticationException("验证码错误, 请重试.");
        }

        List<User> userList = loginMapper.doLogin(tokentwo.getUsername());
        if(userList.size()>0)
        {
            String password = new String((char[]) token.getCredentials());
            String password1 = EncryptUtils.encryptPassword(password, userList.get(0).getSalt());
            if(userList.get(0).getPassword().equals(password1))
            {
                SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(userList.get(0).getEmail(),password,getName());
                session.setAttribute("kehu",userList.get(0));
                return info;
            }
            else
            {
                throw new IncorrectCredentialsException("密码错误");
            }
        }
        else {
            throw new UnknownAccountException("没有此账户");
        }
	}

    
}
