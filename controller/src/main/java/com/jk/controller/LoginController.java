package com.jk.controller;

import com.jk.entity.Comment;
import com.jk.entity.PageInfo;
import com.jk.entity.Post;
import com.jk.entity.User;
import com.jk.service.LoginServcie;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.SavedRequest;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping()
public class LoginController {

    @Resource
    private LoginServcie loginServcie;

    @GetMapping("")
    public String index(Model model,Integer pn,Integer status,Integer recommend,String category_id,HttpServletRequest req)
    {
        List<Post> emps = loginServcie.getAll(status,model,pn,recommend,category_id);
        PageInfo<Post> pageInfo = new PageInfo<Post>(emps,5);
        model.addAttribute("pageInfo",pageInfo);
        String str = loginServcie.certification(req);
        model.addAttribute("certification",str);
        return "/index";
    }

    @GetMapping("logintz")
    public String logintz()
    {
        return "/index/login";
    }

    @GetMapping("register")
    public String register()
    {
        return "index/register";
    }

    @GetMapping("active")
    public String active()
    {
        return "/index/active";
    }



    @PostMapping(value="doLogin",produces = "application/json; charset=utf-8")
    @ResponseBody
    public Map<String,Object> doLogin(String email, String password, String vercode, HttpServletRequest req)
    {
        UsernamePasswordToken token = new UsernamePasswordToken(email, password, vercode);
        Subject currentUser = SecurityUtils.getSubject();
        Map<String,Object> map = new HashMap<>();

        SavedRequest savedRequest = WebUtils.getSavedRequest(req);//获取shiro存取记录

        if (savedRequest == null || savedRequest.getRequestUrl() == null) {
            //为空 则为正常跳转 但对ajax无效
            map.put("url","/");
        }else {
            //不为空 则为阻拦跳转的网址 返回到前台
            map.put("url",savedRequest.getRequestUrl());
        }

        try {
            currentUser.login(token);
            map.put("msg","登陆成功");
        } catch (UnknownAccountException uae) {
            map.put("msg","没有此账户");
        }catch (IncorrectCredentialsException ice) {
            map.put("msg","密码错误");
        }catch (AuthenticationException ae) {
            map.put("msg","验证码错误, 请重试!");
        }
        return map;
        //String attribute = (String) req.getSession().getAttribute("rand");
        //return  "";
    }


    @PostMapping(value="doRegister",produces = "application/json; charset=utf-8")
    @ResponseBody
    public String doRegister(User user, String vercode,HttpServletRequest req)
    {
        return  loginServcie.insertUser(user,vercode,req);
    }

    @GetMapping("post/{postid}")
    public String post(Model model,@PathVariable("postid")String postid,Integer pn,HttpServletRequest req)
    {
        Post post = loginServcie.tiziXq(postid,req,model);
        model.addAttribute("post",post);
        List<Comment> listComment = loginServcie.listComment(postid,pn);
        PageInfo pageInfo = new PageInfo<>(listComment,5);
        model.addAttribute("pageInfo",pageInfo);
        return "/post/post";
    }





}
