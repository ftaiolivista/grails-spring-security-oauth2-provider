package grails.plugins.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.OAuth2Authentication
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

class OauthSecurityService {
	
	static transactional = false

	def springSecurityService
	def grailsApplication

	boolean isOAuth(){
		springSecurityService.authentication instanceof OAuth2Authentication
	}

	OAuth2Authentication getAuthentication() {
		isOAuth()?springSecurityService.authentication:null
	}

	boolean isLoggedIn() {
		springSecurityService.isLoggedIn()
	}

	String getUsername(){
		springSecurityService.principal instanceof String ?[username:null]:springSecurityService.principal.username
	}

	AuthorizationRequest getAuthorizationRequest() {
		getAuthentication()?.authorizationRequest
	}

	def getScopes(){
		isOAuth()?getAuthorizationRequest()?.scope:[]
	}

	def getPrincipal() {
		isOAuth()?getAuthentication().principal:null
	}
	
	Object getCurrentUser() {
		if (!isLoggedIn()) { return null }
		String className = SpringSecurityUtils.securityConfig.userLookup.userDomainClassName
		def principal = getPrincipal()?:springSecurityService.principal
		grailsApplication.getClassForName(className).get(principal.id)
	}

	boolean isOAuthClientAuth() {
		def authentication = springSecurityService.authentication
		(authentication instanceof OAuth2Authentication) &&
				authentication.isAuthenticated() &&
				authentication.isClientOnly()
	}

	boolean isOAuthUserAuth() {
		def authentication = springSecurityService.authentication
		(authentication instanceof OAuth2Authentication) &&
				authentication.isAuthenticated() &&
				(!authentication.isClientOnly())
	}

	boolean clientHasAnyRole(String... roles) {
		def authentication = springSecurityService.authentication
		if (authentication instanceof OAuth2Authentication) {
			if (authentication.authorizationRequest.authorities) {
				for (String role : roles) {
					if (authentication.authorizationRequest.authorities.contains(role)) {
						return true
					}
				}
			}
		}
		false
	}

	boolean hasAnyScope(def scopes) {
		getScopes().intersect( scopes )
	}
	
	boolean hasScope(def scope){
		scope in getScopes()
		}
	
}
