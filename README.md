# Issuedtokenmixedasymmetricbasic256Sample
This .NET (C#) sample demonstrates how to fetch tokens from IssuedToken* ADFS active endpoints.


Broadly, we have to perform the following steps (in sequence) on the client application:
<ol>
	<li>Using "UserNameWSTrustBinding", client gets token from "usernamemixed" ADFS endpoint.</li>
	<li>Using "IssuedTokenWSTrustBinding", client presents the above token to "issuedtokenmixedsymmetricbasic256" ADFS endpoint, and gets a token in response.</li>
	<li>Using "WS2007FederationHttpBinding", the token is presented during the WCF service operation call.</li>
</ol>
	

<b><u>Steps to make the sample running</u></b>

