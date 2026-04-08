package cn.classloader.gmutil;


import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Base64;

@Slf4j
public class SM2UtilTest {
    @Test
    public void encrypt() throws Exception {
        // 按照业务现实情况生成加密内容
        String content = String.format("02|%s", SM4Util.generateNuccKey());
        log.info("需要加密的内容: {}", content); // 02|jCNxDE5zU6GX2boE
        // 获取公钥
        String thirdEncCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIICzTCCAnCgAwIBAgIFQDIGlUcwDAYIKoEcz1UBg3UFADBhMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSAwHgYDVQQDDBdDRkNBIEFDUyBURVNUIFNNMiBPQ0EzMTAeFw0yMTA0MjMwODU2MjFaFw0yNjA0MjMwODU2MjFaMHgxCzAJBgNVBAYTAkNOMRcwFQYDVQQKDA5DRkNBIFNNMiBPQ0EzMTERMA8GA1UECwwITG9jYWwgUkExGTAXBgNVBAsMEE9yZ2FuaXphdGlvbmFsLTIxIjAgBgNVBAMMGTA1MUB0ZXN0QE5OOTk5OTk5OTk5MDAzQDEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATm9N1VxQ84srmSyO/jSYNwZDxjZMcQqgHMMd/faEKnhxJFcoWuaCN2YoDwrA6LL4yqJXyo8q4MDn+D2Wqv7pYpo4H7MIH4MD8GCCsGAQUFBwEBBDMwMTAvBggrBgEFBQcwAYYjaHR0cDovL29jc3B0ZXN0LmNmY2EuY29tLmNuOjgwL29jc3AwHwYDVR0jBBgwFoAUBMe8+VkBaT6MNDYgYhg83ry1uwwwDAYDVR0TAQH/BAIwADA4BgNVHR8EMTAvMC2gK6AphidodHRwOi8vMjEwLjc0LjQyLjMvT0NBMzEvU00yL2NybDEwNS5jcmwwDgYDVR0PAQH/BAQDAgM4MB0GA1UdDgQWBBQGy0+tSRVOSEIHBx5Q0mS7JWhXPDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDAYIKoEcz1UBg3UFAANJADBGAiEAzQ0YaWtAy6GTIjrDGspYt3kXFg94ELLRo4/lf+ZL/hcCIQDz1IPIZMZIbiSNMG5kL/9jtxGzlis3zK/QfkSMO++riQ==\n" +
                "-----END CERTIFICATE-----";
        ECPublicKeyParameters publicKey = BCECUtil.convertPublicKeyToParameters(SM2CertUtil.getBCECPublicKey(SM2CertUtil.getX509Certificate(thirdEncCert.getBytes(StandardCharsets.UTF_8))));
        // 加密
        byte[] encResBytes = SM2Util.encodeSM2CipherToDER(SM2Util.encrypt(publicKey, content.getBytes(StandardCharsets.UTF_8)));
        log.info(Hex.toHexString(encResBytes));

        // base64编码
        String encRes = Base64.getEncoder().encodeToString(encResBytes);
        log.info(encRes); // MHwCID6hNeo0YvYsT3DHzaVFipsuHbbAq9EJ2z0JzPRwaOa9AiEA3uvkfxN0pQ/TJBCY6b/qn5Px9HjxvDyNaZk6VdInFw4EIAH9gyKigGcKql4UBdu35DSEszMjyLWheqVoveWiTXcNBBNgn9l8IiNvlKc0QNTjeFXlY4b4
    }

    @Test
    public void decrypt() throws Exception {
        String content = "MHsCIDZpmbABYirN9KJ2z4b8zKmahYZOShVQFysfOvF/uSjpAiA+2Fk1xPxIdgqlMZXEfEUsBzlOa5SYTJLeDdX/8Rb1ewQg/7QTo2GFPeIkkvVgoPkLtl2Cq6vSgFsWAnM6uN4RFlYEE6sGT/UMxg2AbsfdjCnhDWXWGzU=";
        // 密钥转换
        String encPrivateKeyStr = "403F82A67D170C021FB364C2104724D890BFD7FF2C389E263BA29234DB7D22F6";
        ECPrivateKeyParameters encPrivateKey = SM2Util.getPrivateKeyParameters(encPrivateKeyStr);
        // 解密
        byte[] contentBytes = Base64.getDecoder().decode(content.getBytes(StandardCharsets.UTF_8));
        String decryptStr = new String(SM2Util.decrypt(encPrivateKey, SM2Util.decodeDERSM2Cipher(contentBytes)));
        log.info(decryptStr);
    }

    @Test
    public void sign() throws CryptoException {
        String content = "签名内容";
        // 密钥转换
        String signPrivateKeyStr = "00C4FCB27BB1718A50116246961AE54792AE598EEDAFE59482DC1CBD3B02827E31";
        ECPrivateKeyParameters signPrivateKey = SM2Util.getPrivateKeyParameters(signPrivateKeyStr);
        // 签名
        log.info(Base64.getEncoder().encodeToString(SM2Util.sign(signPrivateKey, content.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    public void signVerify() throws CertificateException, NoSuchProviderException {
        // Security.addProvider(new BouncyCastleProvider());
        String content = "<MsgHeader><SndDt>2026-02-09T10:15:00</SndDt><MsgTp>farms.105.001.01</MsgTp><InstgId>B0000011000023</InstgId><SignSN>4656410874</SignSN><DgtlEnvlp>MHkCIQCzQBYzpjysAuciSc9CmjaFlP1AwlxmWUxVdaGbvWZaMwIgTBFsaDuti9VhxVJBBEBSB+R51SCymGiLS1hNecTurbkEIC+8ZnX1Lz95DLT1nQSAfla/oJPB30LeDyO+vlX7kEfaBBCv4r8RYlPY4vyWC8AZA89a</DgtlEnvlp><NcrptnSN>4804990718</NcrptnSN></MsgHeader><MsgBody><TrxId>202602091015006568cec4380110200</TrxId><FnTp>01</FnTp><OrgnInstgId>B0000011000078</OrgnInstgId><NtfyDtTm>2026-02-09T10:15:00</NtfyDtTm><DataTrTp>01</DataTrTp><DataTp>01</DataTp><DataCntt>UEsDBBQACAgIAOBRSVwAAAAAAAAAAAAAAABKAAAAQjAwMDAwMTEwMDAwNzhfQzEyOTAxNDEwMDAwMTJfMTAwMV8yMDI2MDIwOTEwMTUwMDY1NjhjZWM0MzgwMTEwMjAwLnR4dC5zZWMBEAHv/lcnjkPRYbKRh+M4nsFqtIyiiojQDoDrttBZRnxuKprfnd2zL92GUbAia5H+ZrMLylzUgb1Rii5jekw4KkRZ6iTKGvuDimHFSAF+Zlz68EwzPKc6kCF9NvRFXaWsTnju4xfGDh7TYA6o8X9BLqF/b+OSQbo9JnrNb7vuc68V9KJYewzOwFoxju7D1W4J23/P4mXbU2kWYP/kg4Xb86Oi0YNv8XCkAttfVTHnft5aNP3k/jaccERG8BTzNa5nwFdzCc/E0sp12Fq5hYdcCAODNL6C2sUEUDHFsGKHvoUjJYeUF2ynInSMtL1siaTTZ3RAlyY5qi3lMfH4YHF2U0enGpEC6U34ICn9k7PFIFwa/HrKUEsHCF/99p8VAQAAEAEAAFBLAQIUABQACAgIAOBRSVxf/fafFQEAABABAABKAAAAAAAAAAAAAAAAAAAAAABCMDAwMDAxMTAwMDA3OF9DMTI5MDE0MTAwMDAxMl8xMDAxXzIwMjYwMjA5MTAxNTAwNjU2OGNlYzQzODAxMTAyMDAudHh0LnNlY1BLBQYAAAAAAQABAHgAAACNAQAAAAA=</DataCntt><OrgnBatchNo>202602091012508633e71c310110200</OrgnBatchNo><OrgnReqId>202602091012508633e71c310110200</OrgnReqId><OrgnReqParam></OrgnReqParam><Desc></Desc></MsgBody></root>";
        String sign = "MEYCIQC8S64PAnDtngcuQLZlkwh2aAI5vrJAVwOHTxhd7vY7DAIhAMROPR0ZHl3ENkHFLRkGYeL7xieiO+yHxQQVOs8tt/xK";
        // 获取公钥
        String thirdSignCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIICyzCCAnCgAwIBAgIFQDIGlUYwDAYIKoEcz1UBg3UFADBhMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSAwHgYDVQQDDBdDRkNBIEFDUyBURVNUIFNNMiBPQ0EzMTAeFw0yMTA0MjMwODU2MjFaFw0yNjA0MjMwODU2MjFaMHgxCzAJBgNVBAYTAkNOMRcwFQYDVQQKDA5DRkNBIFNNMiBPQ0EzMTERMA8GA1UECwwITG9jYWwgUkExGTAXBgNVBAsMEE9yZ2FuaXphdGlvbmFsLTIxIjAgBgNVBAMMGTA1MUB0ZXN0QE5OOTk5OTk5OTk5MDAzQDEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASm/WqfpzHHBHmVm0BQYyk8Yn7+FjvDnXw5L1cHi/+heiAx++wMTYNZUGJao9eddK/HTwiXTaldzOXKOu/GPIPjo4H7MIH4MD8GCCsGAQUFBwEBBDMwMTAvBggrBgEFBQcwAYYjaHR0cDovL29jc3B0ZXN0LmNmY2EuY29tLmNuOjgwL29jc3AwHwYDVR0jBBgwFoAUBMe8+VkBaT6MNDYgYhg83ry1uwwwDAYDVR0TAQH/BAIwADA4BgNVHR8EMTAvMC2gK6AphidodHRwOi8vMjEwLjc0LjQyLjMvT0NBMzEvU00yL2NybDEwNS5jcmwwDgYDVR0PAQH/BAQDAgbAMB0GA1UdDgQWBBT+u+zIwcOruVwiLWPonOw26JivgTAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDAYIKoEcz1UBg3UFAANHADBEAiAF310Z7YnZd8peW2pj4f2JK3GWmTxdkhB4fUox3GR8cQIgOMvJPPZgq6OT0zt5WrHUaOUNN6M411NO8yeTLtHgHOI=\n" +
                "-----END CERTIFICATE-----";
        ECPublicKeyParameters publicKey = BCECUtil.convertPublicKeyToParameters(SM2CertUtil.getBCECPublicKey(SM2CertUtil.getX509Certificate(thirdSignCert.getBytes(StandardCharsets.UTF_8))));
        log.info(String.valueOf(SM2Util.verify(publicKey, content.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(sign))));
    }

    @Test
    public void unsafeIntegerVerify() throws CertificateException, NoSuchProviderException {
        String content = "<root xmlns=\"namespace_string\"><MsgHeader><SndDt>2026-02-09T10:15:00</SndDt><MsgTp>farms.105.001.01</MsgTp><InstgId>B0000011000023</InstgId><SignSN>4656410874</SignSN><DgtlEnvlp>MHkCIQCzQBYzpjysAuciSc9CmjaFlP1AwlxmWUxVdaGbvWZaMwIgTBFsaDuti9VhxVJBBEBSB+R51SCymGiLS1hNecTurbkEIC+8ZnX1Lz95DLT1nQSAfla/oJPB30LeDyO+vlX7kEfaBBCv4r8RYlPY4vyWC8AZA89a</DgtlEnvlp><NcrptnSN>4804990718</NcrptnSN></MsgHeader><MsgBody><TrxId>202602091015006568cec4380110200</TrxId><FnTp>01</FnTp><OrgnInstgId>B0000011000078</OrgnInstgId><NtfyDtTm>2026-02-09T10:15:00</NtfyDtTm><DataTrTp>01</DataTrTp><DataTp>01</DataTp><DataCntt>UEsDBBQACAgIAOBRSVwAAAAAAAAAAAAAAABKAAAAQjAwMDAwMTEwMDAwNzhfQzEyOTAxNDEwMDAwMTJfMTAwMV8yMDI2MDIwOTEwMTUwMDY1NjhjZWM0MzgwMTEwMjAwLnR4dC5zZWMBEAHv/lcnjkPRYbKRh+M4nsFqtIyiiojQDoDrttBZRnxuKprfnd2zL92GUbAia5H+ZrMLylzUgb1Rii5jekw4KkRZ6iTKGvuDimHFSAF+Zlz68EwzPKc6kCF9NvRFXaWsTnju4xfGDh7TYA6o8X9BLqF/b+OSQbo9JnrNb7vuc68V9KJYewzOwFoxju7D1W4J23/P4mXbU2kWYP/kg4Xb86Oi0YNv8XCkAttfVTHnft5aNP3k/jaccERG8BTzNa5nwFdzCc/E0sp12Fq5hYdcCAODNL6C2sUEUDHFsGKHvoUjJYeUF2ynInSMtL1siaTTZ3RAlyY5qi3lMfH4YHF2U0enGpEC6U34ICn9k7PFIFwa/HrKUEsHCF/99p8VAQAAEAEAAFBLAQIUABQACAgIAOBRSVxf/fafFQEAABABAABKAAAAAAAAAAAAAAAAAAAAAABCMDAwMDAxMTAwMDA3OF9DMTI5MDE0MTAwMDAxMl8xMDAxXzIwMjYwMjA5MTAxNTAwNjU2OGNlYzQzODAxMTAyMDAudHh0LnNlY1BLBQYAAAAAAQABAHgAAACNAQAAAAA=</DataCntt><OrgnBatchNo>202602091012508633e71c310110200</OrgnBatchNo><OrgnReqId>202602091012508633e71c310110200</OrgnReqId><OrgnReqParam></OrgnReqParam><Desc></Desc></MsgBody></root>";
        String sign = "MEUCIQCvPNvAgGcERGvamoVQvtqM/hbz/2ILloGLr9LvK/rTdgIgADdr/Xmr1mkDSyg17FMHRa/044A7qgwLbGRMku7uOpw=";
        String signPubCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDQzCCAuegAwIBAgIFRlZBCHQwDAYIKoEcz1UBg3UFADBcMQswCQYDVQQGEwJDTjEwMC4GA1UECgwnQ2hpbmEgRmluYW5jaWFsIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRswGQYDVQQDDBJDRkNBIEFDUyBTTTIgT0NBMzEwHhcNMjMwNDIwMTAwMTEyWhcNMjgwNDIwMTAwMTEyWjB2MQswCQYDVQQGEwJDTjEXMBUGA1UECgwOQ0ZDQSBTTTIgT0NBMzExDjAMBgNVBAsMBUZBUk1TMRkwFwYDVQQLDBBPcmdhbml6YXRpb25hbC0yMSMwIQYDVQQDDBowNTFATlVDQ0BORzQwMDAzMTEwMDAwMThANDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABPSlt8nJPPazkbrPLPFKKNOMzTtktH98ZbV1Gy2sFvfpe3QIPUv01Ufw4WaVbkhVo1n5ZCGP26fnnDZfudhXKuWjggF4MIIBdDBsBggrBgEFBQcBAQRgMF4wKAYIKwYBBQUHMAGGHGh0dHA6Ly9vY3NwLmNmY2EuY29tLmNuL29jc3AwMgYIKwYBBQUHMAKGJmh0dHA6Ly9jcmwuY2ZjYS5jb20uY24vb2NhMzEvb2NhMzEuY2VyMB8GA1UdIwQYMBaAFAjY0SbESH2c7KyY6fF/YrmAzqlFMAwGA1UdEwEB/wQCMAAwSAYDVR0gBEEwPzA9BghggRyG7yoBBDAxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmNmY2EuY29tLmNuL3VzL3VzLTE0Lmh0bTA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3JsLmNmY2EuY29tLmNuL29jYTMxL1NNMi9jcmwyODk0LmNybDAOBgNVHQ8BAf8EBAMCBsAwHQYDVR0OBBYEFBjGVeOakYlTFWdRFlbxZO2P64IdMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAMBggqgRzPVQGDdQUAA0gAMEUCIQDsJVs3kXWDkmxp7lxN/kLeoIVT6o8uMLxk0ztalidQ9QIgd/xZFFfeJWneJKlamxMbLNDbFO6r2mzH5CyB/MtvmYI=\n" +
                "-----END CERTIFICATE-----";
        ECPublicKeyParameters publicKey = BCECUtil.convertPublicKeyToParameters(SM2CertUtil.getBCECPublicKey(SM2CertUtil.getX509Certificate(signPubCert.getBytes(StandardCharsets.UTF_8))));
        log.info(String.valueOf(SM2Util.verify(publicKey, content.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(sign))));
    }
}
