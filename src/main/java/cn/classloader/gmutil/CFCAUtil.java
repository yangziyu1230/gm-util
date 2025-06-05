package cn.classloader.gmutil;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

/**
 * CFCA工具类，主要用于生成、解析p10及证书密码
 */
@Slf4j
public class CFCAUtil extends GMBaseUtil {
    public static String generatePKCS10(String dn) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CryptoException {
        // 生成签名密钥
        final KeyPair signKeyPair = SM2Util.generateKeyPair();
        final String signPrivateKey = parsePrivateKey(signKeyPair.getPrivate());
        final String signPublicKey = parsePublicKey(signKeyPair.getPublic());
        log.info("签名证书私钥: {}", signPrivateKey);

        // 生成临时密钥
        final KeyPair tmpKeyPair = SM2Util.generateKeyPair();
        final String tmpPrivateKey = parsePrivateKey(tmpKeyPair.getPrivate());
        final String tmpPublicKey = parsePublicKey(tmpKeyPair.getPublic());
        log.info("tmpPrivateKey, 后续解密证书用, 请妥善保管: {}", tmpPrivateKey);

        final String tmpPublicKeyX = tmpPublicKey.substring(0, 64);
        final String tmpPublicKeyY = tmpPublicKey.substring(64);

        // 公钥信息
        final ASN1EncodableVector algorithmVec = new ASN1EncodableVector();
        algorithmVec.add(new ASN1ObjectIdentifier("1.2.840.10045.2.1"));
        algorithmVec.add(new ASN1ObjectIdentifier("1.2.156.10197.1.301"));
        final ASN1EncodableVector subjectPublicKeyInfoVec = new ASN1EncodableVector();
        subjectPublicKeyInfoVec.add(new DERSequence(algorithmVec));
        subjectPublicKeyInfoVec.add(new DERBitString(Hex.decode(String.format("04%s", signPublicKey).getBytes(StandardCharsets.US_ASCII))));

        // challengePassword
        final ASN1EncodableVector chalPwdVec = new ASN1EncodableVector();
        chalPwdVec.add(new ASN1ObjectIdentifier("1.2.840.113549.1.9.7"));
        chalPwdVec.add(new DERPrintableString("111111"));

        // 临时公钥
        final ASN1EncodableVector tmpPubKeyVec = new ASN1EncodableVector();
        tmpPubKeyVec.add(new ASN1Integer(1));
        final String format = String.format("%s%s%s%s%s",
                "00b4000000010000",
                tmpPublicKeyX,
                "0000000000000000000000000000000000000000000000000000000000000000",
                tmpPublicKeyY,
                "0000000000000000000000000000000000000000000000000000000000000000");
        tmpPubKeyVec.add(new DEROctetString(Hex.decode(format.getBytes(StandardCharsets.US_ASCII))));
        final ASN1EncodableVector tempPublicKeyInfoVec = new ASN1EncodableVector();
        tempPublicKeyInfoVec.add(new ASN1ObjectIdentifier("1.2.840.113549.1.9.63"));
        tempPublicKeyInfoVec.add(new DEROctetString(new DERSequence(tmpPubKeyVec)));

        // Attributes
        ASN1EncodableVector attrVec = new ASN1EncodableVector();
        attrVec.add(new DERSequence(chalPwdVec));
        attrVec.add(new DERSequence(tempPublicKeyInfoVec));

        // DN等信息
        final ASN1EncodableVector certificationRequestInfoVec = new ASN1EncodableVector();
        certificationRequestInfoVec.add(new ASN1Integer(0));
        certificationRequestInfoVec.add(new DERSequence(parseDn(dn)));
        certificationRequestInfoVec.add(new DERSequence(subjectPublicKeyInfoVec));
        certificationRequestInfoVec.add(new DERTaggedObject(false, 0, new DLSequence(attrVec)));

        // 签名
        final byte[] reqInf = new DERSequence(certificationRequestInfoVec).getEncoded();
        final byte[] der = SM2Util.sign((BCECPrivateKey) signKeyPair.getPrivate(), reqInf);
        final String der2Raw = der2Raw(Hex.toHexString(der).toUpperCase(Locale.ROOT));
        final ASN1EncodableVector signVec = new ASN1EncodableVector();
        signVec.add(new ASN1Integer(new BigInteger(der2Raw.substring(0, 64), 16)));
        signVec.add(new ASN1Integer(new BigInteger(der2Raw.substring(64), 16)));

        // 补全信息
        final ASN1EncodableVector algorithmIdentifier = new ASN1EncodableVector();
        algorithmIdentifier.add(new ASN1ObjectIdentifier("1.2.156.10197.1.501"));
        algorithmIdentifier.add(DERNull.INSTANCE);
        final DERBitString bitStr = new DERBitString(new DERSequence(signVec).getEncoded());
        final ASN1EncodableVector certificationRequestVec = new ASN1EncodableVector();
        certificationRequestVec.add(new DERSequence(certificationRequestInfoVec));
        certificationRequestVec.add(new DERSequence(algorithmIdentifier));
        certificationRequestVec.add(bitStr);

        return new String(Base64.getEncoder().encode(new DERSequence(certificationRequestVec).getEncoded()), StandardCharsets.US_ASCII);
    }

    public static void parseResult(String tmpPrivateKey, String resp) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException, InvalidCipherTextException {
        final ECPrivateKeyParameters privateKeyParameters = parsePrivateKey(tmpPrivateKey);
        final String encryptDate = decodeAsn1(parseDoubleCsrResult(resp));
        final byte[] bytes = SM2Util.decrypt(privateKeyParameters, Hex.decode(("04" + encryptDate).getBytes(StandardCharsets.US_ASCII)));
        log.info("加密证书私钥: {}", Hex.toHexString(bytes).toUpperCase(Locale.ROOT).substring(128));
    }

    private static String parsePrivateKey(PrivateKey privateKey) {
        BigInteger d = ((ECPrivateKey) privateKey).getD();
        return Hex.toHexString(d.toByteArray()).toUpperCase();
    }

    private static String parsePublicKey(PublicKey publicKey) {
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECPoint q = ecPublicKey.getQ();
        BigInteger x = q.getAffineXCoord().toBigInteger();
        BigInteger y = q.getAffineYCoord().toBigInteger();
        return String.format("%064x%064x", x, y);
    }

    private static ASN1EncodableVector parseDn(String dn) {
        ASN1EncodableVector subjectVec = new ASN1EncodableVector();
        String[] dnParts = dn.split(",", -1);

        for (String dnPart : dnParts) {
            String[] kv = dnPart.split("=", -1);
            if (kv.length != 2) {
                throw new IllegalArgumentException("Invalid DN part: " + dnPart);
            }
            String key = kv[0].trim().toUpperCase();
            String value = kv[1].trim();

            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new ASN1ObjectIdentifier(getOidForKey(key)));

            // 强制CN使用DERUTF8String,C使用DERPrintableString
            if ("CN".equals(key)) {
                vec.add(new DERUTF8String(value));
            } else if ("C".equals(key)) {
                vec.add(new DERPrintableString(value));
            } else {
                vec.add(new DERUTF8String(value));
            }

            subjectVec.add(new DERSet(new DERSequence(vec)));
        }

        return subjectVec;
    }

    private static String getOidForKey(String key) {
        switch (key) {
            case "C":
                return "2.5.4.6";
            case "O":
                return "2.5.4.10";
            case "OU":
                return "2.5.4.11";
            case "CN":
                return "2.5.4.3";
            default:
                throw new IllegalArgumentException("Unknown DN key: " + key);
        }
    }

    /**
     * 直接提取对应密文
     *
     * @param input .
     * @return .
     */
    private static String parseDoubleCsrResult(String input) {
        return Optional.ofNullable(input)
                .filter(s -> s.length() >= 80)
                .map(s -> s.substring(80))
                .map(s -> s.replace(",", ""))
                .orElse("");
    }

    /**
     * 解析ASN1格式数据
     *
     * @param encrypt .
     * @return .
     * @throws IOException .
     */
    private static String decodeAsn1(String encrypt) throws IOException {
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(Base64.getDecoder().decode(encrypt.getBytes(StandardCharsets.US_ASCII))));
        ASN1Sequence sequence = (ASN1Sequence) asn1InputStream.readObject();
        ASN1Integer version = (ASN1Integer) sequence.getObjectAt(0);
        ASN1OctetString encryptedPrivateKeyData = (ASN1OctetString) sequence.getObjectAt(1);
        byte[] cipherText = Arrays.copyOfRange(encryptedPrivateKeyData.getOctets(), 0, encryptedPrivateKeyData.getOctets().length);
        String hex = Hex.toHexString(cipherText).toUpperCase(Locale.ROOT);

        log.info("[EncryptedPrivateKey-ASN1] version: {}", version);
        log.info("[EncryptedPrivateKey-ASN1] 密文数据: {}", hex);
        return hex;
    }

    /**
     * (hex) 142长度的der签名 -> 128位长度的裸签名
     *
     * @param derHex142 .
     * @return .
     */
    private static String der2Raw(String derHex142) throws IOException {
        String res = "";
        StringBuilder sb = new StringBuilder();

        byte[] decoded = Hex.decode(derHex142.getBytes(StandardCharsets.US_ASCII));
        try (ASN1InputStream ais = new ASN1InputStream(decoded)) {
            ASN1Primitive primitive = ais.readObject();
            if (primitive instanceof ASN1Sequence) {
                ASN1Sequence sequence = (ASN1Sequence) primitive;
                for (ASN1Encodable encodable : sequence) {
                    ASN1Primitive asn1Primitive = encodable.toASN1Primitive();
                    if (asn1Primitive instanceof ASN1Integer) {
                        BigInteger value = ((ASN1Integer) asn1Primitive).getValue();
                        sb.append(String.format("%064x", value));
                    }
                }
            }
        }
        return sb.toString().toUpperCase();
    }

    /**
     * 加载私钥 64位hex值
     *
     * @param hexPrivateKey .
     * @return .
     * @throws NoSuchAlgorithmException .
     * @throws NoSuchProviderException  .
     * @throws InvalidKeySpecException  .
     */
    private static ECPrivateKeyParameters parsePrivateKey(String hexPrivateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        return BCECUtil.createECPrivateKeyParameters(BigIntegers.fromUnsignedByteArray(Hex.decode(hexPrivateKey)), SM2Util.DOMAIN_PARAMS);
    }
}
