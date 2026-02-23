import { SDJwt } from "@sd-jwt/core";
import type { HasherAndAlg } from "@sd-jwt/types";
import { CredentialParsingError } from "../error";
import { Context, CredentialParser, HttpClient } from "../interfaces";
import { CredentialClaimPath, CredentialFriendlyNameCallback, ImageDataUriCallback, MetadataWarning, VerifiableCredentialFormat, TypeMetadata } from "../types";
import { SdJwtVcPayloadSchema } from "../schemas";
import { CredentialRenderingService } from "../rendering";
import { getSdJwtVcMetadata } from "../utils/getSdJwtVcMetadata";
import { OpenID4VCICredentialRendering } from "../functions/openID4VCICredentialRendering";
import { z } from 'zod';
import { getIssuerMetadata } from "../utils/getIssuerMetadata";
import { matchDisplayByLocale } from '../utils/matchLocalizedDisplay';
import { TypeMetadata as TypeMetadataSchema } from "../schemas/SdJwtVcTypeMetadataSchema";
import { convertOpenid4vciToSdjwtvcClaims } from "../functions/convertOpenid4vciToSdjwtvcClaims";

export function SDJWTVCParser(args: { context: Context, httpClient: HttpClient }): CredentialParser {
	const encoder = new TextEncoder();

	function extractValidityInfo(jwtPayload: { exp?: number, iat?: number, nbf?: number }): { validUntil?: Date, validFrom?: Date, signed?: Date } {
		let obj = {};
		if (jwtPayload.exp) {
			obj = {
				...obj,
				validUntil: new Date(jwtPayload.exp * 1000),
			}
		}
		if (jwtPayload.iat) {
			obj = {
				...obj,
				signed: new Date(jwtPayload.iat * 1000),
			}
		}

		if (jwtPayload.nbf) {
			obj = {
				...obj,
				validFrom: new Date(jwtPayload.nbf * 1000),
			}
		}
		return obj;
	}

	// Encoding the string into a Uint8Array
	const hasherAndAlgorithm: HasherAndAlg = {
		hasher: (data: string | ArrayBuffer, alg: string) => {
			const encoded =
				typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);

			return args.context.subtle.digest(alg, encoded).then((v) => new Uint8Array(v));
		},
		alg: 'sha-256',
	};

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
			if (typeof rawCredential !== 'string') {
				return {
					success: false,
					error: CredentialParsingError.InvalidDatatype
				};
			}

			let credentialFriendlyName: CredentialFriendlyNameCallback = async () => null;
			let dataUri: ImageDataUriCallback = async () => null;

			const warnings: MetadataWarning[] = [];

			const { parsedClaims, parsedHeaders, parsedPayload, err } = await (async () => {
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
            parsedHeaders: headers, 
            parsedPayload: payload, 
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

			const schema = z.enum([VerifiableCredentialFormat.VC_SDJWT, VerifiableCredentialFormat.DC_SDJWT]);
			const typParseResult = await schema.safeParseAsync(parsedHeaders.typ);
			if (typParseResult.error) {
				return {
					success: false,
					error: CredentialParsingError.NotSupportedCredentialType,
				}
			}

			// sd-jwt vc Payload Schema Validation
			let validatedParsedClaims;
			try {
				validatedParsedClaims = SdJwtVcPayloadSchema.parse(parsedClaims);
			} catch (err) {
				return {
					success: false,
					error: CredentialParsingError.InvalidSdJwtVcPayload,
				};
			}

			console.log("validated parsed claims JWT");
			console.log(validatedParsedClaims);


			const { metadata: issuerMetadata } = await getIssuerMetadata(args.httpClient, validatedParsedClaims.iss, warnings);

			const getSdJwtMetadataResult = await getSdJwtVcMetadata(args.context, args.httpClient, rawCredential, validatedParsedClaims, warnings);
			if ('error' in getSdJwtMetadataResult) {
				return {
					success: false,
					error: getSdJwtMetadataResult.error,
				}
			}

			let TypeMetadata: Partial<TypeMetadataSchema> = {};
			let credentialMetadata: TypeMetadataSchema | undefined = undefined;

			const credentialIssuerMetadata = credentialIssuer?.credentialConfigurationId
				? issuerMetadata?.credential_configurations_supported?.[credentialIssuer?.credentialConfigurationId]
				: undefined;

			if (getSdJwtMetadataResult.credentialMetadata) {

				credentialMetadata = getSdJwtMetadataResult.credentialMetadata

				if (credentialMetadata?.claims) {
					TypeMetadata = { claims: credentialMetadata.claims };
				}
			}

			credentialFriendlyName = async (
				preferredLangs: string[] = ['en-US']
			): Promise<string | null> => {

				// 1. Try to match localized credential display
				const credentialDisplayArray = credentialMetadata?.display;
				const credentialDisplayLocalized = matchDisplayByLocale(credentialDisplayArray, preferredLangs);
				if (credentialDisplayLocalized?.name) return credentialDisplayLocalized.name;

				// 2. Try to match localized issuer display
				const issuerDisplayArray = credentialIssuerMetadata?.display;
				const issuerDisplayLocalized = matchDisplayByLocale(issuerDisplayArray, preferredLangs);
				if (issuerDisplayLocalized?.name) return issuerDisplayLocalized.name;

				return 'SD-JWT Verifiable Credential';
			};

			dataUri = async (
				filter?: Array<CredentialClaimPath>,
				preferredLangs: string[] = ['en-US']
			): Promise<string | null> => {

				// 1. Try to match localized credential display
				const credentialDisplayArray = credentialMetadata?.display;
				const credentialDisplayLocalized = matchDisplayByLocale(credentialDisplayArray, preferredLangs);

				// 2. Try to match localized issuer display
				const issuerDisplayArray = credentialIssuerMetadata?.display;
				const issuerDisplayLocalized = matchDisplayByLocale(issuerDisplayArray, preferredLangs);

				const svgTemplateUri = credentialDisplayLocalized?.rendering?.svg_templates?.[0]?.uri || null;
				const simpleDisplayConfig = credentialDisplayLocalized?.rendering?.simple || null;
				console.log("svg Template URi");
				console.log(svgTemplateUri);
				console.log("simple Display Config");
				console.log(simpleDisplayConfig);

				console.log("Validated Parsed Claims");
				console.log(validatedParsedClaims);
				
				console.log("credential Meta data");
				console.log(credentialMetadata);
				// 1. Try SVG template rendering
				if (svgTemplateUri) {
					const svgResponse = await args.httpClient.get(svgTemplateUri, {}, { useCache: true }).catch(() => null);
					if (svgResponse && svgResponse.status === 200) {
						const svgdata = svgResponse.data as string;
						const rendered = await cr.renderSvgTemplate({
							json: validatedParsedClaims,
							credentialImageSvgTemplate: svgdata,
							sdJwtVcMetadataClaims: credentialMetadata?.claims,
							filter,
						}).catch(() => null);
						if (rendered) return rendered;
					}
				}

				// 2. Fallback: simple rendering from credential display
				if (simpleDisplayConfig && credentialDisplayLocalized) {
					const rendered = await renderer.renderCustomSvgTemplate({
						signedClaims: validatedParsedClaims,
						displayConfig: { ...credentialDisplayLocalized, ...simpleDisplayConfig },
					}).catch(() => null);
					if (rendered) return rendered;
				}

				// 3. Fallback: rendering from issuer metadata display
				if (issuerDisplayLocalized) {
					const rendered = await renderer.renderCustomSvgTemplate({
						signedClaims: validatedParsedClaims,
						displayConfig: issuerDisplayLocalized,
					}).catch(() => null);
					if (rendered) return rendered;
				}

				const rendered = await renderer.renderCustomSvgTemplate({
					signedClaims: validatedParsedClaims,
					displayConfig: { name: "SD-JWT Verifiable Credential" },
				}).catch(() => null);
				if (rendered) return rendered;

				// All attempts failed
				return null;
			};

			if (!TypeMetadata?.claims && credentialIssuerMetadata?.claims) {
				const convertedClaims = convertOpenid4vciToSdjwtvcClaims(credentialIssuerMetadata.claims);
				if (convertedClaims?.length) {
					TypeMetadata = { claims: convertedClaims };
				}
			}

			return {
				success: true,
				value: {
					signedClaims: validatedParsedClaims,
					metadata: {
						credential: {
							format: typParseResult.data,
							vct: validatedParsedClaims?.vct as string | undefined ?? "",
							TypeMetadata,
							image: {
								dataUri: dataUri,
							},
							name: credentialFriendlyName,
						},
						issuer: {
							id: validatedParsedClaims.iss,
							name: validatedParsedClaims.iss,
						}
					},
					validityInfo: {
						...extractValidityInfo(validatedParsedClaims)
					},
					warnings: getSdJwtMetadataResult.warnings
				}
			}
		},
	}
}
