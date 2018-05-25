package org.apache.knox.gateway.provider.federation;

import org.apache.knox.gateway.preauth.filter.PreAuthValidationException;
import org.apache.knox.gateway.preauth.filter.RadiusValidator;
import org.junit.Test;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by Shubham A Gupta on 25-May-18.
 */
public class RadiusValidatorTest {

    @Test
    public void testRadiusValidator() throws PreAuthValidationException {
        RadiusValidator ipv = new RadiusValidator();
        final HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getHeader("Authorization")).thenReturn("Basic:c3JvX3Rlc3RAdGVzdC5jb206UGFzc3dvcmQ0NTY=");

        final FilterConfig filterConfig = mock(FilterConfig.class);

        when(filterConfig.getInitParameter(RadiusValidator.RADIUS_AUTH_SERVICE_URL)).thenReturn("https://fdevtest020:443/api/authenticate");
        when(filterConfig.getInitParameter(RadiusValidator.IS_SSL_ENABLED)).thenReturn("true");

        assertTrue(ipv.validate(request, filterConfig));
    }

}
