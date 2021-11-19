package com.iot.demo.clients.sociallogin.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexPageController
{

    @GetMapping(path = "/")
    public String displayIndexPage(Model model)
    {
        return "index";
    }
}

