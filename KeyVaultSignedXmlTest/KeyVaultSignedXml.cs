using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Azure.KeyVault;
using System.Configuration;

public class KeyVaultSignedXml: SignedXml
{
    readonly string applicationId = ConfigurationManager.AppSettings["applicationId"];
    readonly string applicationKey = ConfigurationManager.AppSettings["applicationKey"];

    readonly string keyvaultUri = ConfigurationManager.AppSettings["keyvaultUri"];
    readonly string keyIdentifier = ConfigurationManager.AppSettings["keyName"];
    readonly string keyVersion = ConfigurationManager.AppSettings["keyVersion"];

    private KeyVaultClient keyClient = null;
    public KeyVaultSignedXml(XmlDocument xmlDoc) : base(xmlDoc)
    {
        keyClient = new KeyVaultClient(async (authority, resource, scope) =>
        {
            var adCredential = new ClientCredential(applicationId, applicationKey);
            var authenticationContext = new AuthenticationContext(authority, null);

            var result = await authenticationContext.AcquireTokenAsync(resource, adCredential);
            return result.AccessToken;
        });

    }

    internal new void ComputeSignature()
    {
        // BuildDigestedReferences();
        var methodInfo = typeof(SignedXml).GetMethod("BuildDigestedReferences",
            BindingFlags.Instance | BindingFlags.NonPublic);
        methodInfo.Invoke(this, null);

        SignedInfo.SignatureMethod = XmlDsigRSASHA256Url;

        // See if there is a signature description class defined in the Config file
        SignatureDescription signatureDescription = CryptoConfig.CreateFromName(SignedInfo.SignatureMethod) as SignatureDescription;
        if (signatureDescription == null)
            throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");
        HashAlgorithm hashAlg = signatureDescription.CreateDigest();
        if (hashAlg == null)
            throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");

        // byte[] hashvalue = GetC14NDigest(hashAlg);
        var methodInfo2 = typeof(SignedXml).GetMethod("GetC14NDigest", BindingFlags.Instance | BindingFlags.NonPublic);
        var hashvalue = (byte[])methodInfo2.Invoke(this, new object[] { hashAlg });

        m_signature.SignatureValue = CreateSignature(hashvalue).GetAwaiter().GetResult();
    }

    private async Task<byte[]> CreateSignature(byte[] digest)
    {
        var sresult = await keyClient.SignAsync(keyvaultUri, keyIdentifier, keyVersion,
                Microsoft.Azure.KeyVault.WebKey.JsonWebKeySignatureAlgorithm.RS256, digest);
        return sresult.Result;         
    }

    public new bool CheckSignature()
    {
        var methodInfo = typeof(SignedXml).GetMethod("CheckSignatureFormat",
                BindingFlags.Instance | BindingFlags.NonPublic);

        // if (!CheckSignatureFormat())    
        if (!(bool)methodInfo.Invoke(this, null))
        {
            return false;
        }

        if (!CheckSignedInfo().GetAwaiter().GetResult())
        {
            return false;
        }

        // Now is the time to go through all the references and see if their DigestValues are good
        var methodInfo2 = typeof(SignedXml).GetMethod("CheckDigestedReferences",
                BindingFlags.Instance | BindingFlags.NonPublic);
        
        //if (!CheckDigestedReferences())
        if (!(bool)methodInfo2.Invoke(this, null))
        {
            return false;
        }
        return true;
    }

    private async Task<bool> CheckSignedInfo()
    {        
        SignatureDescription signatureDescription = CryptoConfig.CreateFromName(SignedInfo.SignatureMethod) as SignatureDescription;
        if (signatureDescription == null)
            throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");

        HashAlgorithm hashAlgorithm = signatureDescription.CreateDigest();
        if (hashAlgorithm == null)
            throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
        
        //byte[] hashval = GetC14NDigest(hashAlgorithm);        
        var methodInfo2 = typeof(SignedXml).GetMethod("GetC14NDigest", BindingFlags.Instance | BindingFlags.NonPublic);
        var hashvalue = (byte[])methodInfo2.Invoke(this, new object[] { hashAlgorithm });

        var result = await keyClient.VerifyAsync(keyvaultUri, keyIdentifier, keyVersion, 
            Microsoft.Azure.KeyVault.WebKey.JsonWebKeySignatureAlgorithm.RS256, hashvalue, m_signature.SignatureValue);
        return (bool)result.Value;
    }
}