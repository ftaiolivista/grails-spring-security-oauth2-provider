/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.apache.log4j.Logger;
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices
import org.springframework.security.oauth2.provider.BaseClientDetails
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore
import org.springframework.security.oauth2.provider.token.DefaultTokenServices
//import org.springframework.security.oauth2.provider.filter.OAuth2ExceptionHandlerFilter
import grails.plugins.springsecurity.oauthprovider.GormTokenServices
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter
import org.springframework.security.oauth2.provider.approval.TokenServicesUserApprovalHandler

import grails.plugins.springsecurity.oauthprovider.SpringSecurityOAuth2ProviderUtility
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider

import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter
import org.springframework.http.converter.StringHttpMessageConverter
import org.springframework.http.converter.ByteArrayHttpMessageConverter
import org.springframework.http.converter.FormHttpMessageConverter
import org.springframework.http.converter.xml.SourceHttpMessageConverter
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter

class SpringSecurityOauth2ProviderGrailsPlugin {
	static Logger log = Logger.getLogger('grails.app.bootstrap.BootStrap')
	
	def version = "1.0.0.RELEASE"
	String grailsVersion = '1.2.2 > *'
	
	List pluginExcludes = [
		'docs/**',
		'src/docs/**',
		// Domains
		'test/**',
		// Controllers
		'grails-app/controllers/**',
		'grails-app/domain/**',
		'grails-app/i18n/**',
		// Views
		'web-app/**',
		'grails-app/views/login/**',
		'grails-app/views/secured/**',
		'grails-app/views/index.gsp',
	]

	//Map dependsOn = [springSecurityCore: '1.0 > *']
	def loadAfter = ["springSecurityCore"]

	def license = "APACHE"
	def organization = [ name:"Adaptive Computing", url:"http://adaptivecomputing.com" ]
	def issueManagement = [ system:"GitHub", url:"http://github.com/adaptivecomputing/grails-spring-security-oauth2-provider/issues" ]
	def scm = [ url:"http://github.com/adaptivecomputing/grails-spring-security-oauth2-provider" ]

	String author = 'Brian Saville'
	String authorEmail = 'bsaville@adaptivecomputing.com'
	String title = 'OAuth2 Provider support for the Spring Security plugin.'
	String description = '''\
OAuth2 Provider support for the Spring Security plugin.
'''

	String documentation = 'http://grails.org/plugin/spring-security-oauth2-provider'

	def doWithSpring = {

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		SpringSecurityUtils.loadSecondaryConfig 'DefaultOAuth2ProviderSecurityConfig'
		// have to get again after overlaying DefaultOAuthProviderSecurityConfig
		conf = SpringSecurityUtils.securityConfig
		
		if (!conf.oauthProvider.active)
			return

		log.debug 'Configuring Spring Security OAuth2 provider ...'
		
		clientDetailsService(InMemoryClientDetailsService)
		tokenStore(InMemoryTokenStore)
		tokenServices(GormTokenServices) {
			tokenStore = ref("tokenStore")
			clientDetailsService = ref("clientDetailsService")
			accessTokenValiditySeconds = conf.oauthProvider.tokenServices.accessTokenValiditySeconds
			refreshTokenValiditySeconds = conf.oauthProvider.tokenServices.refreshTokenValiditySeconds
			reuseRefreshToken = conf.oauthProvider.tokenServices.reuseRefreshToken
			supportRefreshToken = conf.oauthProvider.tokenServices.supportRefreshToken
		}		
		authorizationCodeServices(InMemoryAuthorizationCodeServices)		
		userApprovalHandler(TokenServicesUserApprovalHandler){
			tokenServices = ref("tokenServices")
		}
		
		redirectResolver(org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver)
		
		// Oauth namespace
		xmlns oauth:"http://www.springframework.org/schema/security/oauth2"
						
		oauth.'authorization-server'(
				'client-details-service-ref':"clientDetailsService",
				'token-services-ref':"tokenServices",
				'authorization-endpoint-url':conf.oauthProvider.authorizationEndpointUrl,
				'user-approval-page':conf.oauthProvider.userApprovalEndpointUrl,
				'approval-parameter-name':conf.oauthProvider.authorizationCode.approvalParameterName,
				'user-approval-handler-ref': 'userApprovalHandler',
				'token-endpoint-url':conf.oauthProvider.tokenEndpointUrl,
				'redirect-resolver-ref': 'redirectResolver' 
				) {
			
			oauth.'authorization-code'(
				'services-ref':"authorizationCodeServices",
				'disabled':!conf.oauthProvider.grantTypes.authorizationCode				
				)
			
			oauth.'implicit'(
				'disabled':!conf.oauthProvider.grantTypes.implicit
			)
			oauth.'refresh-token'(
				'disabled':!conf.oauthProvider.grantTypes.refreshToken
			)
			oauth.'client-credentials'(
				'disabled':!conf.oauthProvider.grantTypes.clientCredentials
			)
			oauth.'password'(
				'authentication-manager-ref':'authenticationManager',
				'disabled':!conf.oauthProvider.grantTypes.password
			)
			for(granter in conf.oauthProvider.customGreantTypes){
				oauth.'custom-grant'(
					'token-granter-ref': "${granter}TokenGranter"
				)
			}
		}
					
		xmlns securityNs:"http://www.springframework.org/schema/security"

		clientDetailsUserService(ClientDetailsUserDetailsService, ref('clientDetailsService'))

		securityNs.'authentication-manager'(id:'clientAuthenticationManager'){
			securityNs.'authentication-provider'('user-service-ref':"clientDetailsUserService")
			}					
		
		oauth.'resource-server'(
			'id': 'resourceServerFilter', 
			'resource-id': 'likella',
			'token-services-ref': 'tokenServices')
		
		SpringSecurityUtils.registerFilter 'resourceServerFilter', conf.oauthProvider.filterStartPosition + 1
			
		// Register endpoint URL filter since we define the URLs above
		clientCredentialsTokenEndpointFilter(ClientCredentialsTokenEndpointFilter){
			authenticationManager = ref('clientAuthenticationManager')
			}		
		SpringSecurityUtils.registerFilter 'clientCredentialsTokenEndpointFilter', conf.oauthProvider.filterStartPosition + 2								
		
		log.debug "... done configured Spring Security OAuth2 provider"
		
		annotationHandlerAdapter(RequestMappingHandlerAdapter){
			messageConverters = [
				new StringHttpMessageConverter(writeAcceptCharset: false),
				new ByteArrayHttpMessageConverter(),
				new FormHttpMessageConverter(),
				new SourceHttpMessageConverter(),
				new MappingJacksonHttpMessageConverter()
				]
			}
		
	}

    def doWithApplicationContext = { applicationContext ->
		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		SpringSecurityUtils.loadSecondaryConfig 'DefaultOAuth2ProviderSecurityConfig'
		// have to get again after overlaying DefaultOAuthProviderSecurityConfig
		conf = SpringSecurityUtils.securityConfig
		
		if (!conf.oauthProvider.active || !conf.oauthProvider.clients)
			return

		log.debug 'Configuring OAuth2 clients ...'
		
		def clientDetailsService = applicationContext.getBean("clientDetailsService")
		if (clientDetailsService instanceof InMemoryClientDetailsService)
			SpringSecurityOAuth2ProviderUtility.registerClients(conf, clientDetailsService)
		else
			log.info("Client details service bean is not an in-memory implementation, ignoring client config")
		
		log.debug '... done configuring OAuth2 clients'
    }
	
    def onConfigChange = { event ->
		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		SpringSecurityUtils.loadSecondaryConfig 'DefaultOAuth2ProviderSecurityConfig'
		// have to get again after overlaying DefaultOAuthProviderSecurityConfig
		conf = SpringSecurityUtils.securityConfig
		
		if (!conf.oauthProvider.active || !conf.oauthProvider.clients)
			return

		log.debug 'Reconfiguring OAuth2 clients ...'
		
		def clientDetailsService = applicationContext.getBean("clientDetailsService")
		if (clientDetailsService instanceof InMemoryClientDetailsService)
			SpringSecurityOAuth2ProviderUtility.registerClients(conf, clientDetailsService)
		else
			log.info("Client details service bean is not an in-memory implementation, ignoring config change")
		
		log.debug '... done reconfiguring OAuth2 clients'
	}
}
