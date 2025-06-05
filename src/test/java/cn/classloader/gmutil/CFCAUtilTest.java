package cn.classloader.gmutil;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * 已经过三方测试可正常申请证书
 */
@Slf4j
public class CFCAUtilTest {
    @Test
    public void genP10() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, NoSuchProviderException, CryptoException {
        Security.addProvider(new BouncyCastleProvider());
        /**
         * 签名证书私钥: 00C4FCB27BB1718A50116246961AE54792AE598EEDAFE59482DC1CBD3B02827E31
         * tmpPrivateKey, 后续解密证书用, 请妥善保管: 00E577411E46255359F563D53163CDC2754DDED6BC1201F9AABBCD1A8497ABA5BA
         * p10: MIIB+jCCAZ0CAQAwgYIxLzAtBgNVBAMMJjA1MUBaWUJBTksgRkFSTVNATjkxNDEwMDAwMzE3NDE2NzVYNkAxMRkwFwYDVQQLDBBPcmdhbml6YXRpb25hbC0yMQ4wDAYDVQQLDAVGQVJNUzEXMBUGA1UECgwOQ0ZDQSBTTTIgT0NBMzExCzAJBgNVBAYTAkNOMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEt+aksSCtswuBdLhBIgc2NuJCTRnrxWC+8myVvNoOvz0pBwLaPdAehRFjhuylZ22WAiz0ukETI+6dvZmZbrKr+6CBtzATBgkqhkiG9w0BCQcTBjExMTExMTCBnwYJKoZIhvcNAQk/BIGRMIGOAgEBBIGIALQAAAABAACNC8Hx8kXgk4OL9dTgslOoEFwFrPe/taQ1qj1HPYjNngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB01NSmAtxv+A196IDawT2fxk63CL8nobKYDifH0IEyQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAMBggqgRzPVQGDdQUAA0kAMEYCIQCwTMtQifVkNmTISh59fg2tkjgVFRfWezCvTl1V1ODefgIhANleJrmM4MsU4fBun3JqXx0vDhdXD4WDTWRkbZyBTIv5
         */
        String dn = "CN=051@ZYBANK FARMS@N9141000031741675X6@1,OU=Organizational-2,OU=FARMS,O=CFCA SM2 OCA31,C=CN";
        log.info("p10: {}", CFCAUtil.generatePKCS10(dn));
    }

    @Test
    public void getEncPriKey() throws InvalidCipherTextException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        String resp = "00000000000000010000000000000001000000000000000000000000000000000000000000000273MIHGAgECBIHARGFcHv04YQSUM4Y5fv9HBQpi1m9Gf6ogT1bkGJg9wiyyfpPaQBsG,REEen4E43wz7H37z1n9Z5HItoPIMkJp+1tKMf4DLQsupeTEItYZCjwrFShMBnmSi,b5slpC3nguRI9CGGHrClezBTYvn2N+ET5Mz8ys1pvDSay0vEFQHV0mzVfClrv/Tx,j8MZUsGGY5os+j3sERySjwfbPyrTuR0gb4WUNLI5Zs+4/qQ+UiJkyZ+mpzP7uAaB,/f9Pt3pbpAZy,";
        CFCAUtil.parseResult("00E577411E46255359F563D53163CDC2754DDED6BC1201F9AABBCD1A8497ABA5BA", resp);
        // 加密证书私钥: 403F82A67D170C021FB364C2104724D890BFD7FF2C389E263BA29234DB7D22F6
    }
}
