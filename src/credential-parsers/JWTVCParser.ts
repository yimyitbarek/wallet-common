import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { 
  CredentialClaimPath, 
  CredentialFriendlyNameCallback, 
  ImageDataUriCallback, 
  MetadataWarning, 
  VerifiableCredentialFormat, 
  TypeMetadata 
} from "../types";
import { CredentialRenderingService } from "../rendering";
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { matchDisplayByLocale } from '../utils/matchLocalizedDisplay';
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { z } from 'zol';

export function JWTVCParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {
  
  function extractValidityInfo(jwtPayload: any) {
    let obj: any = {};
    if (jwtPayload.exp) obj.validUntil = new Date(jwtPayload.exp * 1000);
    if (jwtPayload.iat) obj.signed = new Date(jwtPayload.iat * 1000);
    if (jwtPayload.nbf) obj.validFrom = new Date(jwtPayload.nbf * 1000);
    return obj;
  }

  const cr = CredentialRenderingService();
  const renderer = OpenID4VCICredentialRendering({ httpClient: args.httpClient });

  return {
    async parse({ rawCredential, credentialIssuer }) {
      if (typeof rawCredential !== 'string') {
        return { success: false, error: CredentialParsingError.InvalidDatatype };
      }

      const warnings: MetadataWarning[] = [];

      // 1. Basic JWT Decoding (No SD-JWT logic needed)
      let parsedPayload: any;
      let parsedHeaders: any;
      try {
        const parts = rawCredential.split('.');
        if (parts.length !== 3) throw new Error("Invalid JWT format");
        
        parsedHeaders = JSON.parse(atob(parts[0]));
        parsedPayload = JSON.parse(atob(parts[1]));
      } catch (err) {
        return { success: false, error: CredentialParsingError.CouldNotParse };
      }

      // 2. Format Validation
      // Here we strictly check for jwt_vc_json
      if (parsedHeaders.typ !== "jwt_vc_json") {
        return { success: false, error: CredentialParsingError.NotSupportedCredentialType };
      }

      // 3. Fetch Metadata
      const { metadata: issuerMetadata } = await getIssuerMetadata(args.httpClient, parsedPayload.iss, warnings);
      
      const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
        ? issuerMetadata?.credential_configurations_supported?.[credentialIssuer?.credentialConfigurationId]
        : undefined;

      // 4. Setup Display Callbacks
      const credentialFriendlyName: CredentialFriendlyNameCallback = async (preferredLangs = ['en-US']) => {
        const display = matchDisplayByLocale(credentialIssuerMetadata?.display, preferredLangs);
        return display?.name || 'Verifiable Credential';
      };

      const dataUri: ImageDataUriCallback = async (filter, preferredLangs = ['en-US']) => {
        const display = matchDisplayByLocale(credentialIssuerMetadata?.display, preferredLangs);
        if (display) {
          const rendered = await renderer.renderCustomSvgTemplate({
            signedClaims: parsedPayload,
            displayConfig: display,
          }).catch(() => null);
          if (rendered) return rendered;
        }
        return null;
      };

      return {
        success: true,
        value: {
          signedClaims: parsedPayload,
          metadata: {
            credential: {
              // We cast this to the specific format expected by your library's types
              format: "jwt_vc_json" as any, 
              vct: parsedPayload.vct || "",
              TypeMetadata: { claims: [] }, // JWT VC usually uses issuer metadata for claims
              image: { dataUri },
              name: credentialFriendlyName,
            },
            issuer: {
              id: parsedPayload.iss,
              name: parsedPayload.iss,
            }
          },
          validityInfo: extractValidityInfo(parsedPayload),
          warnings
        }
      };
    },
  };
}