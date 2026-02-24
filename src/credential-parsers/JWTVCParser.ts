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
import { JwtVcPayloadSchema } from "../schemas";
import { getJwtVcMetadata } from "../utils/getJwtVcMetadata";



export function JWTVCParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {
  
  function extractValidityInfo(jwtPayload: any) {
    let obj: any = {};
    if (jwtPayload.exp) obj.validUntil = new Date(jwtPayload.exp * 1000);
    if (jwtPayload.iat) obj.signed = new Date(jwtPayload.iat * 1000);
    if (jwtPayload.nbf) obj.validFrom = new Date(jwtPayload.nbf * 1000);
    return obj;
  }

	/**
 * Decodes a Base64URL string into a Uint8Array.
 * JWT parts (header, payload) are encoded in this format.
 */
function fromBase64Url(base64url: string): Uint8Array {
  // 1. Convert Base64URL to standard Base64
  // Replace '-' with '+' and '_' with '/'
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  
  // 2. Add back padding if necessary
  const pad = base64.length % 4;
  if (pad === 2) {
    base64 += '==';
  } else if (pad === 3) {
    base64 += '=';
  }

  // 3. Decode Base64 string to binary
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  
  return bytes;
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

			const { parsedClaims, parsedHeaders2, parsedPayload2, err } = await (async () => {
        try {
          // Standard JWTs are dot-separated (Header.Payload.Signature)
          const parts = rawCredential.split('.');
          if (parts.length !== 3) {
            throw new Error("Invalid JWT format");
          }

          // Decode Header and Payload using your utility (e.g., fromBase64Url)
          const headers = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0])));
          const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[1])));

          /**
           * In W3C JWTVC, the 'claims' are typically found inside vc.credentialSubject.
           * We set parsedClaims to the payload itself so your flattening logic 
           * can run on it later.
           */
          return { 
            parsedClaims: payload as Record<string, unknown>, 
            parsedHeaders2: headers, 
            parsedPayload2: payload, 
            err: null 
          };
        }
        catch (error) {
          console.error("JWTVC Decoding failed:", error);
          return { parsedClaims: null, parsedHeaders: null, parsedPayload: null, err: error };
        }
      })();

      if (err || !parsedPayload || !parsedHeaders) {
        return {
          success: false,
          error: CredentialParsingError.CouldNotParse,
        };
      }
			console.log("parsed Claims JWTVC");
			console.log(parsedClaims);
			// sd-jwt vc Payload Schema Validation
			let validatedParsedClaims;
			try {
				validatedParsedClaims = JwtVcPayloadSchema.parse(parsedClaims);
			} catch (err) {
			//	return {
			//		success: false,
			//		error: CredentialParsingError.InvalidSdJwtVcPayload,
				console.log("validated Parsed Claims error");
				console.log(err);	
			};
			//}
			console.log("validated Parsed Claims JWTVC");
			console.log(validatedParsedClaims);

      // 3. Fetch Metadata
      const { metadata: issuerMetadata } = await getIssuerMetadata(args.httpClient, "https://agent.dev.eduwallet.nl/nlgov", warnings);


			const getJwtMetadataResult = await getJwtVcMetadata(
				args.context, 
				args.httpClient, 
				rawCredential, 
				validatedParsedClaims as Record<string, unknown>, 
				warnings
			);
			console.log("get JWT Metadata Result");
			console.log(getJwtMetadataResult);			
			if ('error' in getJwtMetadataResult) {
							return {
								success: false,
								error: getJwtMetadataResult.error,
							}
						}
      
			const ISSUER_URL = 'https://agent.dev.eduwallet.nl/nlgov/.well-known/openid-credential-issuer';

			// 2. Fetch the metadata from the website
			const issuerResponse = await args.httpClient.get(ISSUER_URL);
			const issuerMetadata2 = issuerResponse.data as any;
			
			/** * 3. Find the specific configuration for 'jwt_vc_json'.
			 * The issuer supports multiple formats (PID and PID_SD). 
			 * We filter for the one matching your requirement.
			 */
			const configurations = issuerMetadata2.credential_configurations_supported || {};
			const pidConfig2 = Object.values(configurations).find(
				(config: any) => config.format === 'jwt_vc_json'
			) as any;
			
			// 4. Extract the display and claim metadata
			const credentialMetadata = pidConfig2?.credential_metadata || {};

			console.log("Credential Metadata from url");
			console.log(credentialMetadata);
      //const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
      //  ? issuerMetadata?.credential_configurations_supported?.[credentialIssuer?.credentialConfigurationId]
      //  : undefined;
			console.log("issuer Metadata");
			console.log(issuerMetadata);

			// 1. Access the specific "PID" config from the issuer metadata
			const pidConfig = issuerMetadata?.credential_configurations_supported?.['PID'];
			console.log("Pid config");
			console.log(pidConfig);
			// 2. Extract the English display specifically for our internal use
			const englishDisplay = pidConfig?.display?.find((d: any) => d.locale === 'en') 
														|| pidConfig?.display?.[0];

			console.log("English display");
			console.log(englishDisplay);
			// 3. OVERRIDE: Set the metadata variable used by the callbacks below
			// This ensures matchDisplayByLocale finds the 'PID' specific branding
			const credentialIssuerMetadata = issuerMetadata;

			// 4. Setup Display Callbacks
			const credentialFriendlyName: CredentialFriendlyNameCallback = async (preferredLangs = ['en']) => {
				// Now this will correctly find the name from the PID config we set above
				const display = matchDisplayByLocale(credentialIssuerMetadata?.display, preferredLangs);
				console.log("display");
				console.log(display);
				return display?.name || 'Personal ID';
			};

			const dataUri: ImageDataUriCallback = async (
				filter?: Array<CredentialClaimPath>,
				preferredLangs: string[] = ['en']
			): Promise<string | null> => {

				// 1. Resolve Metadata & Display
				const credentialDisplayLocalized = matchDisplayByLocale(credentialIssuerMetadata?.display, preferredLangs);
				const displayMetadata = (credentialDisplayLocalized || englishDisplay) as any;
				
				const svgTemplateUri = "https://issuer.yitbarek-dev.app.siros.org/images/template-pid.svg";//displayMetadata?.rendering?.svg_templates?.[0]?.uri || null;
				
				console.log("Credential Display Localized");
				console.log(credentialDisplayLocalized);

				console.log("displayedMetadata");
				console.log(displayMetadata);
				
				console.log("svgTemplateUri");
				console.log(svgTemplateUri);

				// 2. Prepare Flattened Claims (Flattening logic you requested)
				const credentialSubject = (parsedPayload.vc?.credentialSubject || parsedPayload.credentialSubject || parsedPayload) as any;
				
				let rawPicture = parsedPayload.picture || credentialSubject.picture || credentialSubject.portrait || null;
				if (rawPicture && typeof rawPicture === 'string' && !rawPicture.startsWith('data:') && !rawPicture.startsWith('http')) {
					rawPicture = `data:image/jpeg;base64,${rawPicture}`;
				}

				const normalizedClaims2 = {
					...parsedPayload,
					...credentialSubject,
					picture: rawPicture
				};
				const manualClaimsMetadata2 = [
					{ path: ['family_name'], svg_id: 'family_name' },
					{ path: ['given_name'], svg_id: 'given_name' },
					{ path: ['picture'], svg_id: 'picture' },
					{ path: ['birth_date'], svg_id: 'birth_date' },
					{ path: ['expiry_date'], svg_id: 'expiry_date' }
				];
				// 1. Get the raw claims from the fetched metadata
				const rawClaims = pidConfig2?.credential_metadata?.claims as any || [];

				// 2. Map them to your desired format
				const manualClaimsMetadata = rawClaims.map((claim: any) => {
					// Extract the actual field name (the last element in the path array)
					// Source: ["credentialSubject", "family_name"] -> Target: "family_name"
					const fieldName = claim.path[claim.path.length - 1];
    
					// Handle the specific rename: 'portrait' -> 'picture'
					const isPortrait = fieldName === 'portrait';
					const finalId = isPortrait ? 'picture' : fieldName;
					return {
						path: [finalId],
						svg_id: finalId
					};
				});

				// 3. Optional: Filter for specific fields if you don't want all 28
				const whitelist = ['family_name', 'given_name', 'portrait', 'birth_date', 'expiry_date'];
				const filteredClaimsMetadata = manualClaimsMetadata.filter((c: any) => 
					whitelist.includes(c.svg_id)
				);
				console.log("normalized Claims 2");
				console.log(normalizedClaims2);
				// STEP 1: SVG Template Rendering
				let rend =  null;
				// STEP 1: SVG Template Rendering
				if (svgTemplateUri) {
					const svgResponse = await args.httpClient.get(svgTemplateUri, {}, { useCache: true }).catch(() => null);
					if (svgResponse && svgResponse.status === 200) {
						const svgdata = svgResponse.data as string;
						
						const rendered = await cr.renderSvgTemplate({
							json: normalizedClaims2,
							credentialImageSvgTemplate: svgdata,
							// FIX: Changed 'undefined' to '[]' to prevent the .reduce() crash
							sdJwtVcMetadataClaims: filteredClaimsMetadata, 
							filter,
						}).catch((err) => {
							console.error("SVG Internal Error:", err);
							return null;
						});
						rend = rendered;
						if (rendered) return rendered;
					}
				}

				// STEP 3: Generic PID Fallback (Using your English metadata)
				const pidDefaultDisplay = {
					name: displayMetadata?.name || "Person Identification Data",
					logo: displayMetadata?.logo || { uri: "https://nl.gov.dev.eduwallet.nl/images/nlgov_credential_logo.png" },
					background_color: displayMetadata?.background_color || "#003399", 
					text_color: displayMetadata?.text_color || "#FFFFFF",
				};

				//const finalFallback = await renderer.renderCustomSvgTemplate({
				//	signedClaims: normalizedClaims2,
				//	displayConfig: {
				//		...pidDefaultDisplay,
				////		// Ensure the portrait is mapped to the background image for the SVG
				//		background_image: normalizedClaims2.picture ? { uri: normalizedClaims2.picture } : undefined
				//	},
				//}).catch(() => null);

				return rend;
			};

			// 1. Identify the source of the nested claims
			// We look in 'vc.credentialSubject' (W3C standard) or 'credentialSubject'
			const credentialSubject = (parsedPayload.vc?.credentialSubject || parsedPayload.credentialSubject || {}) as any;

			// 2. Extract the picture specifically to handle the 'portrait' naming issue
			const pictureValue = parsedPayload.picture || 
													credentialSubject.picture || 
													credentialSubject.portrait || 
													null;

			// 3. Construct the flattened 'signedClaims'
			const normalizedClaims = {
				...parsedPayload,     // Keep top-level JWT claims (iss, sub, iat, exp)
				...credentialSubject, // This pulls every field from credentialSubject up to the root
				picture: pictureValue // Ensures the UI 'picture' key is populated
			};

			// Clean up: Optional - if you want to remove the redundant nested object
			delete normalizedClaims.vc;
			delete normalizedClaims.credentialSubject;
			// 1. Force the ID right here
			const forceConfigId = "urn:eudi:pid:1:dc";



			return {
				success: true,
				value: {
					// This now contains everything at the top level
					signedClaims: normalizedClaims, 
					metadata: {
						credential: {
							format: parsedHeaders.typ as any, 
							// Force the ID here so it's not empty in your logs/metadata
							vct: parsedPayload.vct || "urn:eudi:pid:1:dc",
							credentialConfigurationId: "urn:eudi:pid:1:dc",
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