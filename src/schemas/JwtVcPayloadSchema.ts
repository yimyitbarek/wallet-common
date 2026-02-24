import { z } from "zod";

export const JwtVcPayloadSchema = z
  .object({
    iss: z.string().min(1),
    sub: z.string().optional(),
    iat: z.number().optional(),
    exp: z.number().optional(),
    // vct is MISSING in JWTVC, so we make it optional to stop the error
    vct: z.string().optional(), 
    vc: z.object({
      "@context": z.array(z.string()),
      type: z.array(z.string()),
      credentialSubject: z.record(z.any()),
    }).passthrough(),
  })
  .passthrough();