package me.mthw.forge;

public class CrackerOptions
{

    public boolean common;
    public String commonCount;
    public boolean strings;
    public String stringsType;

    public boolean decryptFile;


    public boolean randomPassword;
    public int randomPasswordMinLength;
    public int randomPasswordMaxLength;
    public char[] randomPasswordCharSet;

    public boolean tag; 

    public boolean file;
    public String filePath;

    public int threadsCount = 1;
}
