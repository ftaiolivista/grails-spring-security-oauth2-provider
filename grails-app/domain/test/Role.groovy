package test

class Role {

	String authority

	static mapping = {
		cache true
		autoImport false		
	}

	static constraints = {
		authority blank: false, unique: true
	}
}
