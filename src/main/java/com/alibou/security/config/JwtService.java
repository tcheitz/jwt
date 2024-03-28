package com.alibou.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY="20Fc0aF4c9ac9E3b065A00E633229cac29422018d0435489D88B701Fe79bCA45Ed80Ba807Be53A3200654b777B8b97e9eb890921F4Be3f266D38c5a0C5B412F87fE76C9582371180988C646498ecA94b272d3EF1c4F2fAb68A9fc124340f6A12b86C3753c08ce17863fD1029C173919B61a167e5e71c887a3edCcFe5006B5EDfbEC6A173f0867f56891b3dDB08F2a0C46E0aD0d0Cdf2E7C6E196d17bcFA8fc02Ae70749C2be15B6Fe821ad7Ad583D3005B6c4b602C42A54956d577482dCbCeEe80910FF182B987725682b53651b2E9c1b94C55B1eefd5b07eDb2508B58E00eb7ac61c46865eE5272eb40fa0D61Ad44f09D5Cf6483321f18A73e0AddC40d7835F780369cF44c855429B90E7800c3cd921F532aE6fd154dFbB58EDCec48581787fECA6993eAf4e8cE112a00E0Ef21a3b91cd741cb2149BA66f6A2ad58836D00B76";
    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public  String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }
    public String generateToken(Map<String,Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .claims().empty().add(extraClaims).and()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+120000))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token,UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
//        return Jwts.SIG.HS256.key().build();
    }
}
