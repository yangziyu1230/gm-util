package cn.classloader.gmutil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class GMBaseUtil {
    static {
        Security.addProvider(new BouncyCastleProvider());
        // ASN1的INTEGER第一位为0时，部分加密机也会加0x00，关闭对integer校验，相见ASN1Integer.isMalformed(byte[])
        System.setProperty("org.bouncycastle.asn1.allow_unsafe_integer", "true");
    }
}
