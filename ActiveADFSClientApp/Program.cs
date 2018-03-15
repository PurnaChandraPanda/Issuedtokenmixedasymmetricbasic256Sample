using Microsoft.WSTrust.HelperBindings;
using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using System.Configuration;
using ActiveADFSClientApp.ServiceReference1;

namespace ActiveADFSClientApp
{
    class Program
    {
        static void Main(string[] args)
        {
            var tokenType = ConfigurationManager.AppSettings["saml10TokenType"].ToString();
            bool isSAML10Token;
            Boolean.TryParse(tokenType, out isSAML10Token);
            if (isSAML10Token)
            {
                tokenType = "urn:oasis:names:tc:SAML:1.0:assertion";
            }
            else
            {
                tokenType = "urn:oasis:names:tc:SAML:2.0:assertion";
            }

            var usernameToken = GetIdentityProviderToken(tokenType);

            var issuedToken = GetRSTSToken(usernameToken, tokenType);

            var serviceResponse = CallService_IssuedToken(issuedToken);

            Console.WriteLine(serviceResponse);
            Console.ReadLine();
        }

        private static SecurityToken GetIdentityProviderToken(string tokenType)
        {
            var binding = new UserNameWSTrustBinding(SecurityMode.TransportWithMessageCredential);

            var factory = new WSTrustChannelFactory(binding, ConfigurationManager.AppSettings["usernamemixedEP"].ToString())
            {
                TrustVersion = TrustVersion.WSTrust13
            };

            factory.Credentials.UserName.Password = ConfigurationManager.AppSettings["password"].ToString();
            factory.Credentials.UserName.UserName = ConfigurationManager.AppSettings["username"].ToString();
            factory.Credentials.SupportInteractive = false;
            factory.Credentials.UseIdentityConfiguration = true;

            var rst = new RequestSecurityToken
            {
                RequestType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
                AppliesTo = new EndpointReference(ConfigurationManager.AppSettings["usernamemixedAppliesTo"].ToString()),
                KeyType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey",
                TokenType = tokenType
            };

            var channel = factory.CreateChannel();
            return channel.Issue(rst);
        }
        
        private static SecurityToken GetRSTSToken(SecurityToken token, string tokenType)
        {
            var binding = new IssuedTokenWSTrustBinding();
            binding.SecurityMode = SecurityMode.TransportWithMessageCredential;

            var issuredTokenEP = ConfigurationManager.AppSettings["issuedtokenEP"].ToString();
            if (issuredTokenEP.ToLower().EndsWith("issuedtokenmixedasymmetricbasic256sha256")
                || issuredTokenEP.ToLower().EndsWith("issuedtokenmixedsymmetricbasic256sha256"))
            {
                binding.AlgorithmSuite = SecurityAlgorithmSuite.Basic256Sha256;
            }

            var factory = new WSTrustChannelFactory(binding, issuredTokenEP);
            factory.TrustVersion = TrustVersion.WSTrust13;
            factory.Credentials.SupportInteractive = false;
            factory.Credentials.UseIdentityConfiguration = true;
            
            var rst = new RequestSecurityToken
            {
                RequestType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
                AppliesTo = new EndpointReference(ConfigurationManager.AppSettings["issuedtokenAppliesTo"].ToString()),
                KeyType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer",
                TokenType = tokenType,
            };

            var channel = factory.CreateChannelWithIssuedToken(token);

            return channel.Issue(rst);
        }

        private static string CallService_IssuedToken(SecurityToken token)
        {
            // Creating the channel and calling it
            var binding = new WS2007FederationHttpBinding(WSFederationHttpSecurityMode.TransportWithMessageCredential);
            binding.Security.Message.IssuedKeyType = SecurityKeyType.BearerKey;

            var serviceEpAddress = ConfigurationManager.AppSettings["serviceEpAddress"].ToString();
            var factory = new ChannelFactory<IService1>(binding, new EndpointAddress(serviceEpAddress));
            
            // Create a channel
            IService1 client = factory.CreateChannelWithIssuedToken(token);
            
            // Invoke the service operation
            var response = client.GetData(12);
            ((IClientChannel)client).Close();

            return response;
        }

    }
}
