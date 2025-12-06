
import java.net.MalformedURLException;
import java.net.URL;


public class Main {
    public static void main(String[] args) throws MalformedURLException {
        String urlStr = "https://baidu.com/mkt/1?sas=1";
        URL url = new URL(urlStr);
        System.out.println(url.getPath());
    }

}