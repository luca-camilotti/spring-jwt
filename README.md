# Spring JWT

A Spring Boot Rest service with JWT implementation.
See AppUtils.java for token configuration:

```java
public class AppUtils {
	
	public static final int tokenDurationMs = 2*60*1000; // 2 mins
	public static final int refreshTokenDurationMs = 30*60*1000; // 30 mins
	public static final String secret = "Kj67-@#_4Tr2.Pzw:0<Lf45!pq78";

}

```

### Authentication

The authentication api is `/api/login`
Send username and password in x-www-form-urlencoded format.

### Token refresh

Use `/api/token/refresh` api to refresh the token.
