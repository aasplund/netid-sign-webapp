package se.vgregion.sign.proto;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class SignController {

    @RequestMapping(value = "/sign")
    //@RequestMapping(value = "/sign", method = RequestMethod.POST)
    public void sign(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String dataToSign = "foo"; //request.getParameter("data");
        String callback = "http://example.com"; //request.getParameter("callback");
        
        String postBackUrl = "postback?callback=" + URLEncoder.encode(callback, "UTF-8");
        
        PrintWriter writer = response.getWriter();

        writer.write("<html>");
        writer.write("<head>");
        writer.write("<title></title>");
        writer.write("</head>");
        writer.write("<body>");
        writer.write("<OBJECT NAME='iid' WIDTH=0 HEIGHT=0 CLASSID='CLSID:5BF56AD2-E297-416E-BC49-00B327C4426E'>");
        writer.write("<PARAM NAME='DataToBeSigned' VALUE='" + dataToSign + "'>");
        writer.write("<PARAM NAME='DirectActivation' VALUE='Sign'>");
        writer.write("<PARAM NAME='IncludeCaCert' VALUE='true'>");
        writer.write("<PARAM NAME='IncludeRootCaCert' VALUE='true'>");
        writer.write("<PARAM NAME='PostURL' VALUE='" + postBackUrl + "'>");
        writer.write("<PARAM NAME='Base64' VALUE='true'>");

        writer.write("<OBJECT NAME='iid' WIDTH=0 HEIGHT=0 TYPE='application/x-iid'>");
        writer.write("<PARAM NAME='DataToBeSigned' VALUE='" + dataToSign + "'>");
        writer.write("<PARAM NAME='IncludeCaCert' VALUE='true'>");
        writer.write("<PARAM NAME='IncludeRootCaCert' VALUE='true'>");
        writer.write("<PARAM NAME='DirectActivation' VALUE='Sign'>");
        writer.write("<PARAM NAME='PostURL' VALUE='" + postBackUrl + "'>");
        writer.write("<PARAM NAME='Base64' VALUE='true'>");
        writer.write("</OBJECT>");
        writer.write("</OBJECT>");
        writer.write("</body>");
        writer.write("</html>");
    }
    
    @RequestMapping(value = "/postback")
    public void postback(HttpServletRequest request, HttpServletResponse response) throws IOException, CMSException, GeneralSecurityException {

        String signedAsBase64 = request.getParameter("SignedData");
        String callback = request.getParameter("callback");
        
        byte[] pkcs7 = Base64.decodeBase64(signedAsBase64);
        
        if(verify(pkcs7)) {
            // TODO gör en redirect tillbaka till den callback. 
            // Hur går man bäst detta? Autosubitta ett formulär?
            // Signaturen är sannolikt för stor för att skicka i en GET
            response.getWriter().write("Verified");
        } else {
            // TODO redirect med fel
            response.getWriter().write("Not verified");
        }
    }
    
    private boolean verify(byte[] signed) throws CMSException, GeneralSecurityException {
        Security.addProvider(new BouncyCastleProvider());

        CMSSignedData signedData = new CMSSignedData(signed);
        
        CertStore certs = signedData.getCertificatesAndCRLs("Collection", "BC");
        
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        
        boolean verified = true;
        for(SignerInformation signer : signers) {
            Collection<? extends Certificate> signerCerts = certs.getCertificates(signer.getSID());

            for(Certificate cert : signerCerts) {
                X509Certificate x509Cert = (X509Certificate) cert;

                if (!signer.verify(x509Cert.getPublicKey(), "BC")) {
                    verified = false;
                }
            }
        }
        return verified;

    }
}
