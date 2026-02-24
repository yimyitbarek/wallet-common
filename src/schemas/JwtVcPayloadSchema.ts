import { z } from "zod";

export const JwtVcPayloadSchema = z
  .object({
    // Root level W3C v2 fields
    "@context": z.array(z.string()),
    iss: z.string(),
    sub: z.string().optional(),
    iat: z.number().optional(),
    exp: z.number().optional(),
    
    // In your log, these are at the root
    issuer: z.union([z.string(), z.record(z.any())]).optional(),
    type: z.array(z.string()),
    
    // This is where your Martin Jørgensen data lives
    credentialSubject: z.record(z.any()),
    
    credentialStatus: z.array(z.record(z.any())).optional(),
    validFrom: z.string().optional(),
    validUntil: z.string().optional(),
  })
  .passthrough(); 

export type JwtVcPayload = z.infer<typeof JwtVcPayloadSchema>;