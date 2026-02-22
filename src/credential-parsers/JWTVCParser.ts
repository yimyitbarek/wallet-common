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
			
				// 1. Match the localized display from issuer metadata
				const credentialDisplayLocalized = matchDisplayByLocale(credentialIssuerMetadata?.display, preferredLangs);
				
				// Cast to 'any' to bypass the "Property 'rendering' does not exist" error
				const displayMetadata = credentialDisplayLocalized as any;
				
				const svgTemplateUri = displayMetadata?.rendering?.svg_templates?.[0]?.uri || null;
				const simpleDisplayConfig = displayMetadata?.rendering?.simple || null;
			
				// STEP 1: SVG Template Rendering (High Priority)
				if (svgTemplateUri) {
					const svgResponse = await args.httpClient.get(svgTemplateUri, {}, { useCache: true }).catch(() => null);
					if (svgResponse && svgResponse.status === 200) {
						const svgdata = svgResponse.data as string;
						
						// For vc+jwt, the SVG often expects the internal credentialSubject claims
						const renderContext = parsedPayload.vc?.credentialSubject || parsedPayload;
			
						const rendered = await cr.renderSvgTemplate({
							json: renderContext,
							credentialImageSvgTemplate: svgdata,
							sdJwtVcMetadataClaims: undefined,
							filter,
						}).catch(() => null);
						
						if (rendered) return rendered;
					}
				}
			
				// STEP 2: Custom SVG Rendering (Fallback 1)
				if (credentialDisplayLocalized) {
					const rendered = await renderer.renderCustomSvgTemplate({
						// Pass the full payload here as the renderer usually handles its own mapping
						signedClaims: parsedPayload,
						displayConfig: { 
							...credentialDisplayLocalized, 
							...(simpleDisplayConfig ?? {}) 
						},
					}).catch(() => null);
					
					if (rendered) return rendered;
				}
			
				// STEP 3: Generic Card (Fallback 2)
				const finalFallback = await renderer.renderCustomSvgTemplate({
					signedClaims: parsedPayload,
					displayConfig: { name: "Verifiable Credential" },
				}).catch(() => null);
			
				return finalFallback;
			};

			// 1. Target the internal claims
			const credentialSubject = (parsedPayload.vc?.credentialSubject || parsedPayload.credentialSubject || {}) as any;

			// 2. Normalize: Ensure 'picture' exists for the UI
			// We look for 'picture' first, then 'portrait', then 'photo' inside the subject
			const pictureValue = parsedPayload.picture || 
													credentialSubject.picture || 
													credentialSubject.portrait || 
													credentialSubject.photo || 
													null;
			const effectiveConfigId = credentialIssuer?.credentialConfigurationId || "urn:eudi:pid:1:dc";

			const normalizedClaims = {
				...parsedPayload,
				...credentialSubject,
				picture: pictureValue,
				credentialConfigurationId: effectiveConfigId
			};
			console.log("display claims");
			console.log(normalizedClaims);
			// 1. Force the ID right here
			const forceConfigId = "urn:eudi:pid:1:dc";

			return {
				success: true,
				value: {
					signedClaims: normalizedClaims,
					metadata: {
						credential: {
							// This is the specific field the Wallet usually maps to 'credentialConfigurationId'
							format: parsedHeaders.typ as any,
							vct: parsedPayload.vct || forceConfigId, 
							
							// ADD THIS LINE: Explicitly tell the system what configuration this is
							credentialConfigurationId: forceConfigId, 
							
							TypeMetadata: { claims: [] },
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