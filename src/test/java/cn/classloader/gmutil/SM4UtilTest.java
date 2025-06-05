package cn.classloader.gmutil;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;

@Slf4j
public class SM4UtilTest {
    @Test
    public void encrypt() throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        String key = "1111111111111111";
        String encStr = "rDEk3IFzpbgp8nnH57DMsg==";
        byte[] resBytes = SM4Util.decryptECBPadding(key.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(encStr));
        String res = new String(resBytes, StandardCharsets.UTF_8);
        log.info(res);
    }

    @Test
    public void decrypt() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        String key = "aaa1111111111111";
        String content = "sm4测试";
        byte[] encBytes = SM4Util.encryptECBPadding(key.getBytes(StandardCharsets.UTF_8), content.getBytes(StandardCharsets.UTF_8));
        log.info(Base64.getEncoder().encodeToString(encBytes));
    }
}
