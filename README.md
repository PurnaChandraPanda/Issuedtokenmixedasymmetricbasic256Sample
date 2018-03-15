# Issuedtokenmixedasymmetricbasic256Sample
This .NET (C#) sample demonstrates how to fetch tokens from IssuedToken* ADFS active endpoints.


Broadly, we have to perform the following steps (in sequence) on the client application:
<ol>
	<li>Using "UserNameWSTrustBinding", client gets token from "usernamemixed" ADFS endpoint.</li>
	<li>Using "IssuedTokenWSTrustBinding", client presents the above token to "issuedtokenmixedsymmetricbasic256" ADFS endpoint, and gets a token in response.</li>
	<li>Using "WS2007FederationHttpBinding", the token is presented during the WCF service operation call.</li>
</ol>
	

<b>Steps to make the sample running</b>:
<ol>
	<li>Download the whole sample</li>
	<li>Service application <b>Issuedtokenmixedasymmetricbasic256WcfService1</b> can be hosted on IIS</li>
	<li>Ensure ADFS is provisoned as per the screenshots in <a target="_blank" href="https://blogs.msdn.microsoft.com/dsnotes/2018/03/15/wif-fetch-saml-tokens-from-issuedtoken-endpoint-for-backend-service-call" rel="noopener">blog</a></li>
	<li>Configure your endpoints in client application configuration file of <b>ActiveADFSClientApp</b></li>
	<li>Run the app now</li>
<ol>

