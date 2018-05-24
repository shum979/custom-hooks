/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.knox.gateway.preauth.filter;

import com.google.common.annotations.VisibleForTesting;
import org.apache.knox.gateway.audit.api.*;
import org.apache.knox.gateway.audit.log4j.audit.AuditConstants;
import org.apache.knox.gateway.filter.AbstractGatewayFilter;
import org.apache.knox.gateway.security.PrimaryPrincipal;
import org.apache.shiro.codec.Base64;

import javax.security.auth.Subject;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;
import java.util.Set;

/**
 *
 */
public abstract class AbstractPreAuthFederationFilter implements Filter {

  private List<PreAuthValidator> validators = null;
  private FilterConfig filterConfig;
  private static AuditService auditService = AuditServiceFactory.getAuditService();
  private static Auditor auditor = auditService.getAuditor(
      AuditConstants.DEFAULT_AUDITOR_NAME, AuditConstants.KNOX_SERVICE_NAME,
      AuditConstants.KNOX_COMPONENT_NAME );

  /**
   * 
   */
  public AbstractPreAuthFederationFilter() {
    super();
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    this.filterConfig = filterConfig;
    validators = PreAuthService.getValidators(filterConfig);
  }

  @VisibleForTesting
  public List<PreAuthValidator> getValidators() {
    return validators;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest)request;
    // String principal = getPrimaryPrincipal(httpRequest);

      String principal = getCredentials(httpRequest).split(":")[0];

      if (principal != null) {
      if (PreAuthService.validate(httpRequest, filterConfig, validators)) {
        Subject subject = new Subject();
        subject.getPrincipals().add(new PrimaryPrincipal(principal));
        addGroupPrincipals(httpRequest, subject.getPrincipals());
        auditService.getContext().setUsername( principal ); //KM: Audit Fix
        String sourceUri = (String)request.getAttribute( AbstractGatewayFilter.SOURCE_REQUEST_CONTEXT_URL_ATTRIBUTE_NAME );
        auditor.audit( Action.AUTHENTICATION , sourceUri, ResourceType.URI, ActionOutcome.SUCCESS );
        doAs(httpRequest, response, chain, subject);
      }
      else {
        // TODO: log preauthenticated SSO validation failure
        ((HttpServletResponse)response).sendError(HttpServletResponse.SC_FORBIDDEN, "SSO Validation Failure.");
      }
    } 
    else {
      ((HttpServletResponse)response).sendError(HttpServletResponse.SC_FORBIDDEN, "Missing Required Header for PreAuth SSO Federation");
    }
  }

  @Override
  public void destroy() {
  }

  private void doAs(final ServletRequest request, final ServletResponse response, final FilterChain chain, Subject subject)
    throws IOException, ServletException {
    try {
      Subject.doAs(
          subject,
          new PrivilegedExceptionAction<Object>() {
            public Object run() throws Exception {
              chain.doFilter(request, response);
              return null;
            }
          }
          );
    }
    catch (PrivilegedActionException e) {
      Throwable t = e.getCause();
      if (t instanceof IOException) {
        throw (IOException) t;
      }
      else if (t instanceof ServletException) {
        throw (ServletException) t;
      }
      else {
        throw new ServletException(t);
      }
    }
  }
  
  /**
   * @param httpRequest
   */
  abstract protected String getPrimaryPrincipal(HttpServletRequest httpRequest);

  /**
   * @param principals
   */
  abstract protected void addGroupPrincipals(HttpServletRequest request, Set<Principal> principals);


  protected String getCredentials(HttpServletRequest httpRequest){
      String encodedPrincipal = httpRequest.getHeader("Authorization");
      String credentials = Base64.decodeToString(encodedPrincipal.substring(6));

      return credentials;
  }
}