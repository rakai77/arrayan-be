import { describe, it, expect } from 'vitest'
import { loginSchema } from './auth.schema.js'

describe('loginSchema validation', () => {
  it('harus menerima email dan password yang valid', () => {
    const validData = {
      email: 'user@arrayan.com',
      password: 'Password123!',
    }

    const result = loginSchema.safeParse(validData)
    expect(result.success).toBe(true)
  })

  it('harus menolak format email yang salah', () => {
    const invalidEmail = {
      email: 'bukan-email',
      password: 'Password123!',
    }

    const result = loginSchema.safeParse(invalidEmail)
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('Format email tidak valid')
    }
  })

  it('harus menolak password kurang dari 6 karakter', () => {
    const shortPassword = {
      email: 'user@arrayan.com',
      password: '123',
    }

    const result = loginSchema.safeParse(shortPassword)
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues[0]?.message).toBe('Password minimal 6 karakter')
    }
  })
})
