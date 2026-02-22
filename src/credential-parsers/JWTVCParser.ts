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
import { z } from 'zod';

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
			console.log("JWTV parsing started")
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

				console.log("parts");
				console.log(parts);
      } catch (err) {
        return { success: false, error: CredentialParsingError.CouldNotParse };
      }
			console.log("parsed headers");
			console.log(parsedHeaders);
      // 2. Format Validation
      // Here we strictly check for jwt_vc_json
			const supportedTypes = ["vc+jwt", "jwt_vc_json"];

			if (!supportedTypes.includes(parsedHeaders.typ)) {
				return { 
					success: false, 
					error: CredentialParsingError.NotSupportedCredentialType 
				};
			}
			console.log("parsedPayload issuer");
			console.log(parsedPayload.iss);

      // 3. Fetch Metadata
      const { metadata: issuerMetadata } = await getIssuerMetadata(args.httpClient, "https://agent.dev.eduwallet.nl/nlgov", warnings);
      
      const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
        ? issuerMetadata?.credential_configurations_supported?.[credentialIssuer?.credentialConfigurationId]
        : undefined;
			console.log("issuer Metadata");
			console.log(issuerMetadata);

      // 4. Setup Display Callbacks
      const credentialFriendlyName: CredentialFriendlyNameCallback = async (preferredLangs = ['en-US']) => {
        const display = matchDisplayByLocale(credentialIssuerMetadata?.display, preferredLangs);
        return display?.name || 'Verifiable Credential';
      };

			const dataUri: ImageDataUriCallback = async (
				filter?: Array<CredentialClaimPath>,
				preferredLangs: string[] = ['en-US']
			): Promise<string | null> => {
			
				// 1. Get the display configuration for the specific credential
				const credentialDisplayLocalized = matchDisplayByLocale(credentialIssuerMetadata?.display, preferredLangs);
				
				const svgTemplateUri = credentialDisplayLocalized?.rendering?.svg_templates?.[0]?.uri || null;
				const simpleDisplayConfig = credentialDisplayLocalized?.rendering?.simple || null;
			
				// STEP 1: Try SVG template rendering (High quality)
				if (svgTemplateUri) {
					const svgResponse = await args.httpClient.get(svgTemplateUri, {}, { useCache: true }).catch(() => null);
					if (svgResponse && svgResponse.status === 200) {
						const svgdata = svgResponse.data as string;
						const rendered = await cr.renderSvgTemplate({
							json: parsedPayload, // Use the decoded JWT payload
							credentialImageSvgTemplate: svgdata,
							// For JWT-VC, we often don't have SD-JWT style claim metadata, so we pass undefined or the issuer's claim info
							sdJwtVcMetadataClaims: undefined, 
							filter,
						}).catch(() => null);
						if (rendered) return rendered;
					}
				}
			
				// STEP 2: Fallback to Simple Rendering (The logic you currently have)
				if (credentialDisplayLocalized) {
					const rendered = await renderer.renderCustomSvgTemplate({
						signedClaims: parsedPayload,
						displayConfig: { 
							...credentialDisplayLocalized, 
							...(simpleDisplayConfig ?? {}) 
						},
					}).catch(() => null);
					if (rendered) return rendered;
				}
			
				// STEP 3: Final Fallback (Generic card)
				const finalRendered = await renderer.renderCustomSvgTemplate({
					signedClaims: parsedPayload,
					displayConfig: { name: "Verifiable Credential" },
				}).catch(() => null);
			
				return finalRendered;
			};

      return {
        success: true,
        value: {
          signedClaims: parsedPayload,
          metadata: {
            credential: {
              // We cast this to the specific format expected by your library's types
              format: parsedHeaders.typ as any, 
              vct: parsedPayload.vct || parsedPayload.vc?.type?.[0] || "",
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