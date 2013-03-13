import java.util.Map;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;
import org.springframework.security.oauth2.provider.implicit.Authentication;
import org.springframework.security.oauth2.provider.implicit.InsufficientAuthenticationException;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

package grails.plugins.springsecurity.oauthprovider

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.provider.AuthorizationRequest
import org.springframework.security.oauth2.provider.TokenGranter
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter

class DeviceCodeTokenGranter implements AbstractTokenGranter {
	
	def deviceCodeService
	
	private static final String GRANT_TYPE = "http://oauth.net/grant_type/device/1.0"
	
	DeviceCodeTokenGranter(AuthorizationServerTokenServices tokenServices, ClientDetailsService clientDetailsService) {
			super(tokenServices, clientDetailsService, GRANT_TYPE)
		}

	public OAuth2AccessToken grant( String grantType, AuthorizationRequest authorizationRequest, def deviceCodeService ) {		
		super.grant(grantType, authorizationRequest)		
		}
		
	@Override
	protected OAuth2Authentication getOAuth2Authentication(AuthorizationRequest authorizationRequest) {

		def parameters = authorizationRequest.authorizationParameters
		
		def deviceCode = parameters.get("code")
		
		if (!deviceCode) {
			throw new OAuth2Exception("A device code must be supplied.")
		}
		
		AuthorizationRequestHolder storedAuth = authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
		if (storedAuth == null) {
			throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
		}

	}
		
		
		
	}

}
