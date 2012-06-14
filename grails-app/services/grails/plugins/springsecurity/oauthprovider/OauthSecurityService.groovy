package grails.plugins.springsecurity.oauthprovider

import org.springframework.security.oauth2.provider.OAuth2Authentication

class OauthSecurityService {

	def springSecurityService

	boolean isOAuth(){
		springSecurityService.authentication instanceof OAuth2Authentication
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
		def authentication = springSecurityService.authentication		
		if (authentication instanceof OAuth2Authentication) {			
			def clientAuthentication = authentication.authorizationRequest				
			return clientAuthentication.getScope().intersect( scopes )			
		}
		false
	}
	
}
