import { z } from 'zod'

export const loginSchema = z.object({
  email: z.string().email({ message: 'Format email tidak valid' }),
  password: z.string().min(6, { message: 'Password minimal 6 karakter' }),
})

export type LoginInput = z.infer<typeof loginSchema>

export interface UserSessionPayload {
  id: string
  email: string
  role: {
    code: string
    name: string
    permissions: string[]
  }
  employee?: {
    id: string
    nik: string
    fullName: string
    jobTitle: string
    department: string | null
    managerId: string | null
  } | null
}
