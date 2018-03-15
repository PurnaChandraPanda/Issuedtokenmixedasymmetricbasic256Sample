using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Xml;

namespace Microsoft.WSTrust.HelperBindings
{
    /// <summary>
    ///     IssuedTokenWSTrustBinding: Client is authenticated with IssuedToken.
    /// </summary>
    public class IssuedTokenWSTrustBinding : WSTrustBindingBase
    {
        public const string WSTrust13Constants_Prefix = "trust";
        public const string WSTrust13Constants_NamespaceURI = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
        public const string WSTrust13Constants_CanonicalizationAlgorithm = "CanonicalizationAlgorithm";
        public const string WSTrust13Constants_SignatureAlgorithm = "SignatureAlgorithm";
        public const string WSTrust13Constants_EncryptWith = "EncryptWith";
        public const string WSTrust13Constants_EncryptionAlgorithm = "EncryptionAlgorithm";
        public const string WSTrust13Constants_KeyWrapAlgorithm = "KeyWrapAlgorithm";

        public const string WSTrustFeb2005Constants_NamespaceURI = "http://schemas.xmlsoap.org/ws/2005/02/trust";
        public const string WSTrustFeb2005Constants_Prefix = "t";
        public const string WSTrustFeb2005Constants_EncryptionAlgorithm = "EncryptionAlgorithm";
        public const string WSTrustFeb2005Constants_EncryptWith = "EncryptWith";
        public const string WSTrustFeb2005Constants_CanonicalizationAlgorithm = "CanonicalizationAlgorithm";
        public const string WSTrustFeb2005Constants_SignatureAlgorithm = "SignatureAlgorithm";

        public IssuedTokenWSTrustBinding()
            : this(null, null)
        {
        }

        public IssuedTokenWSTrustBinding(Binding issuerBinding, EndpointAddress issuerAddress)
            : this(issuerBinding, issuerAddress, SecurityMode.Message, TrustVersion.WSTrust13, null)
        {
        }

        public IssuedTokenWSTrustBinding(Binding issuerBinding, EndpointAddress issuerAddress,
            EndpointAddress issuerMetadataAddress)
            : this(issuerBinding, issuerAddress, SecurityMode.Message, TrustVersion.WSTrust13, issuerMetadataAddress)
        {
        }

        public IssuedTokenWSTrustBinding(Binding issuerBinding, EndpointAddress issuerAddress, string tokenType,
            IEnumerable<ClaimTypeRequirement> claimTypeRequirements)
            : this(issuerBinding, issuerAddress, SecurityKeyType.SymmetricKey, SecurityAlgorithmSuite.Basic256,
                tokenType, claimTypeRequirements)
        {
        }

        public IssuedTokenWSTrustBinding(Binding issuerBinding, EndpointAddress issuerAddress, SecurityMode mode,
            TrustVersion trustVersion, EndpointAddress issuerMetadataAddress)
            : this(issuerBinding, issuerAddress, mode, trustVersion, SecurityKeyType.SymmetricKey,
                SecurityAlgorithmSuite.Basic256, null, null, issuerMetadataAddress)
        {
        }

        public IssuedTokenWSTrustBinding(Binding issuerBinding, EndpointAddress issuerAddress, SecurityKeyType keyType,
            SecurityAlgorithmSuite algorithmSuite, string tokenType,
            IEnumerable<ClaimTypeRequirement> claimTypeRequirements)
            : this(issuerBinding, issuerAddress, SecurityMode.Message, TrustVersion.WSTrust13, keyType, algorithmSuite,
                tokenType, claimTypeRequirements, null)
        {
        }

        public IssuedTokenWSTrustBinding(Binding issuerBinding, EndpointAddress issuerAddress, SecurityMode mode,
            TrustVersion version, SecurityKeyType keyType, SecurityAlgorithmSuite algorithmSuite, string tokenType,
            IEnumerable<ClaimTypeRequirement> claimTypeRequirements, EndpointAddress issuerMetadataAddress)
            : base(mode, version)
        {
            ClaimTypeRequirement = new Collection<ClaimTypeRequirement>();

            if (SecurityMode.Message != mode && SecurityMode.TransportWithMessageCredential != mode)
            {
                throw new InvalidOperationException("ID3226");
            }

            if (KeyType == SecurityKeyType.BearerKey && version == TrustVersion.WSTrustFeb2005)
            {
                throw new InvalidOperationException("ID3267");
            }

            KeyType = keyType;
            AlgorithmSuite = algorithmSuite;
            TokenType = tokenType;
            IssuerBinding = issuerBinding;
            IssuerAddress = issuerAddress;
            IssuerMetadataAddress = issuerMetadataAddress;

            if (claimTypeRequirements != null)
            {
                foreach (ClaimTypeRequirement requirement in claimTypeRequirements)
                {
                    ClaimTypeRequirement.Add(requirement);
                }
            }
        }

        private void AddAlgorithmParameters(SecurityAlgorithmSuite algorithmSuite, TrustVersion trustVersion,
            SecurityKeyType keyType, ref IssuedSecurityTokenParameters issuedParameters)
        {
            issuedParameters.AdditionalRequestParameters.Insert(0,
                CreateEncryptionAlgorithmElement(algorithmSuite.DefaultEncryptionAlgorithm));

            issuedParameters.AdditionalRequestParameters.Insert(0,
                CreateCanonicalizationAlgorithmElement(algorithmSuite.DefaultCanonicalizationAlgorithm));

            string signatureAlgorithm = null;
            string encryptionAlgorithm = null;

            switch (keyType)
            {
                case SecurityKeyType.SymmetricKey:
                    signatureAlgorithm = algorithmSuite.DefaultSymmetricSignatureAlgorithm;
                    encryptionAlgorithm = algorithmSuite.DefaultEncryptionAlgorithm;
                    break;

                case SecurityKeyType.AsymmetricKey:
                    signatureAlgorithm = algorithmSuite.DefaultAsymmetricSignatureAlgorithm;
                    encryptionAlgorithm = algorithmSuite.DefaultAsymmetricKeyWrapAlgorithm;
                    break;

                case SecurityKeyType.BearerKey:
                    return;

                default:
                    throw new ArgumentOutOfRangeException("keyType");
            }

            issuedParameters.AdditionalRequestParameters.Insert(0, CreateSignWithElement(signatureAlgorithm));
            issuedParameters.AdditionalRequestParameters.Insert(0, CreateEncryptWithElement(encryptionAlgorithm));

            if (trustVersion != TrustVersion.WSTrustFeb2005)
            {
                issuedParameters.AdditionalRequestParameters.Insert(0,
                    CreateKeyWrapAlgorithmElement(algorithmSuite.DefaultAsymmetricKeyWrapAlgorithm));
            }
        }

        protected override void ApplyTransportSecurity(HttpTransportBindingElement transport)
        {
            throw new NotSupportedException();
        }

        private XmlElement CreateCanonicalizationAlgorithmElement(string canonicalizationAlgorithm)
        {
            if (canonicalizationAlgorithm == null)
            {
                throw new ArgumentNullException("canonicalizationAlgorithm");
            }

            XmlDocument document = new XmlDocument();
            XmlElement element = null;

            if (base.TrustVersion == TrustVersion.WSTrust13)
            {
                element = document.CreateElement("trust", "CanonicalizationAlgorithm",
                    "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
            }

            else if (base.TrustVersion == TrustVersion.WSTrustFeb2005)
            {
                element = document.CreateElement("t", "CanonicalizationAlgorithm",
                    "http://schemas.xmlsoap.org/ws/2005/02/trust");
            }

            if (element != null)
            {
                element.AppendChild(document.CreateTextNode(canonicalizationAlgorithm));
            }

            return element;
        }

        private XmlElement CreateEncryptionAlgorithmElement(string encryptionAlgorithm)
        {
            if (encryptionAlgorithm == null)
            {
                throw new ArgumentNullException("encryptionAlgorithm");
            }

            XmlDocument document = new XmlDocument();
            XmlElement element = null;

            if (base.TrustVersion == TrustVersion.WSTrust13)
            {
                element = document.CreateElement("trust", "EncryptionAlgorithm",
                    "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
            }
            else if (base.TrustVersion == TrustVersion.WSTrustFeb2005)
            {
                element = document.CreateElement("t", "EncryptionAlgorithm",
                    "http://schemas.xmlsoap.org/ws/2005/02/trust");
            }

            if (element != null)
            {
                element.AppendChild(document.CreateTextNode(encryptionAlgorithm));
            }

            return element;
        }

        private XmlElement CreateEncryptWithElement(string encryptionAlgorithm)
        {
            if (encryptionAlgorithm == null)
            {
                throw new ArgumentNullException("encryptionAlgorithm");
            }

            XmlDocument document = new XmlDocument();
            XmlElement element = null;

            if (base.TrustVersion == TrustVersion.WSTrust13)
            {
                element = document.CreateElement("trust", "EncryptWith",
                    "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
            }
            else if (base.TrustVersion == TrustVersion.WSTrustFeb2005)
            {
                element = document.CreateElement("t", "EncryptWith", "http://schemas.xmlsoap.org/ws/2005/02/trust");
            }

            if (element != null)
            {
                element.AppendChild(document.CreateTextNode(encryptionAlgorithm));
            }

            return element;
        }

        private static XmlElement CreateKeyWrapAlgorithmElement(string keyWrapAlgorithm)
        {
            if (keyWrapAlgorithm == null)
            {
                throw new ArgumentNullException("keyWrapAlgorithm");
            }

            XmlDocument document = new XmlDocument();
            XmlElement element = document.CreateElement("trust", "KeyWrapAlgorithm",
                "http://docs.oasis-open.org/ws-sx/ws-trust/200512");

            element.AppendChild(document.CreateTextNode(keyWrapAlgorithm));

            return element;
        }

        protected override SecurityBindingElement CreateSecurityBindingElement()
        {
            SecurityBindingElement element;

            IssuedSecurityTokenParameters issuedParameters =
                new IssuedSecurityTokenParameters(TokenType, IssuerAddress, IssuerBinding)
                {
                    KeyType = KeyType,
                    IssuerMetadataAddress = IssuerMetadataAddress
                };

            if (KeyType == SecurityKeyType.SymmetricKey)
            {
                issuedParameters.KeySize = AlgorithmSuite.DefaultSymmetricKeyLength;
            }
            else
            {
                issuedParameters.KeySize = 0;
            }

            if (ClaimTypeRequirement != null)
            {
                foreach (ClaimTypeRequirement requirement in ClaimTypeRequirement)
                {
                    issuedParameters.ClaimTypeRequirements.Add(requirement);
                }
            }

            AddAlgorithmParameters(AlgorithmSuite, base.TrustVersion, KeyType, ref issuedParameters);

            if (SecurityMode.Message == base.SecurityMode)
            {
                element = SecurityBindingElement.CreateIssuedTokenForCertificateBindingElement(issuedParameters);
            }
            else
            {
                if (SecurityMode.TransportWithMessageCredential != base.SecurityMode)
                {
                    throw new InvalidOperationException("ID3226");
                }

                element = SecurityBindingElement.CreateIssuedTokenOverTransportBindingElement(issuedParameters);
            }

            element.DefaultAlgorithmSuite = AlgorithmSuite;
            element.IncludeTimestamp = true;

            return element;
        }

        private XmlElement CreateSignWithElement(string signatureAlgorithm)
        {
            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException("signatureAlgorithm");
            }

            XmlDocument document = new XmlDocument();
            XmlElement element = null;

            if (base.TrustVersion == TrustVersion.WSTrust13)
            {
                element = document.CreateElement("trust", "SignatureAlgorithm",
                    "http://docs.oasis-open.org/ws-sx/ws-trust/200512");
            }
            else if (base.TrustVersion == TrustVersion.WSTrustFeb2005)
            {
                element = document.CreateElement("t", "SignatureAlgorithm",
                    "http://schemas.xmlsoap.org/ws/2005/02/trust");
            }

            if (element != null)
            {
                element.AppendChild(document.CreateTextNode(signatureAlgorithm));
            }

            return element;
        }

        public SecurityAlgorithmSuite AlgorithmSuite { get; set; }
        public Collection<ClaimTypeRequirement> ClaimTypeRequirement { get; private set; }
        public EndpointAddress IssuerAddress { get; set; }
        public Binding IssuerBinding { get; set; }
        public EndpointAddress IssuerMetadataAddress { get; set; }
        public SecurityKeyType KeyType { get; set; }
        public string TokenType { get; set; }
    }
}