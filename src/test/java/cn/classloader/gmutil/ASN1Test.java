package cn.classloader.gmutil;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.IOException;
import java.util.Base64;

public class ASN1Test extends GMBaseUtil {
    @Test
    public void parseAsn1() throws IOException {
        byte[] asn1 = Base64.getDecoder().decode("MEUCIQCvPNvAgGcERGvamoVQvtqM/hbz/2ILloGLr9LvK/rTdgIgADdr/Xmr1mkDSyg17FMHRa/044A7qgwLbGRMku7uOpw=");
        System.out.println(Hex.toHexString(asn1));
        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(asn1);
        System.out.println(seq);
    }
}
