package org.apache.knox.gateway.preauth.filter;

/**
 * Created by Shubham A Gupta on 19-Apr-18.
 */

import com.google.common.base.Strings;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.knox.gateway.GatewayMessages;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.shiro.codec.Base64;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class RadiusValidator implements PreAuthValidator {

    public static final String RADIUS_AUTH_SERVICE_URL = "radius.auth.service.url";
    public static final String IS_SSL_ENABLED = "radius.auth.service.ssl.enable";
    public static final String VERIFIED_HOSTS = "radius.auth.service.hosts";

//    static final String URL = "http://localhost:80/api/authenticate";
//    static final String USER_NAME = "sro_test@test.com";
//    static final String PASSWORD = "UGFzc3dvcmQ0NTY=";


    //Any string constant value should work for these 3 variables
    //This string will be used in 'org.apache.knox.gateway.preauth.filter.PreAuthValidator' file.
    public static final String CUSTOM_VALIDATOR_NAME = "radius.authenticator";
    //Optional: User may want to pass something through HTTP header. (per client request)
    public static final String CUSTOM_TOKEN_HEADER_NAME = "foo_claim";
    private static final GatewayMessages log = MessagesFactory.get(GatewayMessages.class);




    /**
     * @param httpRequest
     * @param filterConfig
     * @return
     * @throws PreAuthValidationException
     */
    public boolean validate(HttpServletRequest httpRequest, FilterConfig filterConfig) throws PreAuthValidationException {

        String url = filterConfig.getInitParameter(RADIUS_AUTH_SERVICE_URL);
        String sslFlag = filterConfig.getInitParameter(IS_SSL_ENABLED);

        String userName = getCredentials(httpRequest).split(":")[0];
        String password = getCredentials(httpRequest).split(":")[1];
        String encodedPass = Base64.encodeToString(password.getBytes());

        String input = "{ \"username\": \"" + userName + "\", \"password\": \"" + encodedPass + "\" }";

        System.out.println("url is : " + url + " username is : " + userName + " encoded password is : " + encodedPass);

        Client client = null;
        try {
            client = getClient(sslFlag);
            WebTarget webTarget = client.target(url);

            Invocation.Builder invocationBuilder =  webTarget.request(MediaType.APPLICATION_JSON);
            Response response = invocationBuilder.post(Entity.entity(input, MediaType.APPLICATION_JSON));

            if (response.getStatus() != 200) {
                System.out.println("Failed : HTTP error code : " + response.getStatus());
                return false;
            }

            String output = response.readEntity(String.class);
            return output.contains("tempToken");

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
            String stackTrace = ExceptionUtils.getStackTrace(e);
            System.out.println(stackTrace);
            return false;
        }
    }

    /**
     * Define unique validator name
     *
     * @return
     */
    public String getName() {
        return CUSTOM_VALIDATOR_NAME;
    }


    private String getCredentials(HttpServletRequest httpRequest){
        String encodedPrincipal = httpRequest.getHeader("Authorization");
        String credentials = Base64.decodeToString(encodedPrincipal.substring(6));
        return credentials;
    }


    private Client getClient(String sslFlag) throws NoSuchAlgorithmException, KeyManagementException {
        boolean isSslEnabled = !Strings.isNullOrEmpty(sslFlag) && Boolean.parseBoolean(sslFlag);

        if(isSslEnabled){
            return sshClient();
        }else {
            return ClientBuilder.newClient();
        }
    }



    private Client sshClient() throws KeyManagementException, NoSuchAlgorithmException {

        System.out.println("SSL is enabled.. creating secure connection");
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, getTrustManager(), null);

        Client client = ClientBuilder
                .newBuilder()
                .hostnameVerifier((String s, SSLSession sslSession) -> true)
                .sslContext(sslContext)
                .build();

        return  client;
    }


    public TrustManager[] getTrustManager() {
        return new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                    }
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                    }
                }
        };
    }
}
