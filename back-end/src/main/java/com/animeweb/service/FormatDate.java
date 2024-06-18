package com.animeweb.service;

import java.text.SimpleDateFormat;
import java.util.Date;

public class FormatDate {
    public static String formatDate(Date date){
        if(date!=null){
            SimpleDateFormat formatter = new SimpleDateFormat("hh:mm:ss a dd/MM/yyyy");
            return formatter.format(date);
        }else{
            return "";
        }
    }
}
