package se.vgregion.sign.proto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CRLTest {

    public static void main(String[] args) throws Exception {
        //InputStream ios = new URL("http://www.carelink.se/siths-ca/ca003.crl").openStream();

        InputStream ios = new URL("http://www.carelink.se/siths-ca/test-crl0003.crl").openStream();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) cf.generateCRL(ios);

        // set up for verifying the CRL signature
        Signature sig = Signature.getInstance(crl.getSigAlgName());
        sig.initVerify(loadTrustedCertificate());
        sig.update(crl.getEncoded());
        
        
        if(sig.verify(crl.getSignature())) {
            for (X509CRLEntry entry : crl.getRevokedCertificates()) {
                // ... 
                System.out.println(entry.getRevocationDate());
            }
            
            Date nextTimeToUpdate = crl.getNextUpdate();
            // use the date as the next time to update the CRL
        } else {
            // handle invalid CRL
            System.out.println("Invalid");
        }
        
        
    }

    private static X509Certificate loadTrustedCertificate() throws FileNotFoundException,
            CertificateException, IOException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream inStream = new FileInputStream("/Users/niklas/Downloads/SITHS CA TEST v3.cer");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
        inStream.close();
        return cert;
    }
}
