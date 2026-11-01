import { describe, it, expect } from 'vitest'
import { refreshSchema } from './auth.schema.js'
import { hashToken, generateOpaqueToken } from './auth.service.js'

describe('auth refresh token & utilities', () => {
  describe('refreshSchema', () => {
    it('harus menerima body tanpa refreshToken (karena bisa dari cookie)', () => {
      const result = refreshSchema.safeParse({})
      expect(result.success).toBe(true)
    })

    it('harus menerima refreshToken string valid', () => {
      const result = refreshSchema.safeParse({ refreshToken: 'abcdef1234567890' })
      expect(result.success).toBe(true)
    })

    it('harus menolak refreshToken yang terlalu pendek (< 10 karakter)', () => {
      const result = refreshSchema.safeParse({ refreshToken: 'short' })
      expect(result.success).toBe(false)
    })
  })

  describe('token hashing utilities', () => {
    it('generateOpaqueToken harus menghasilkan string acak hex 64 karakter', () => {
      const token1 = generateOpaqueToken()
      const token2 = generateOpaqueToken()

      expect(typeof token1).toBe('string')
      expect(token1.length).toBe(64)
      expect(token1).not.toBe(token2)
    })

    it('hashToken harus menghasilkan hash SHA-256 yang konsisten', () => {
      const rawToken = 'test-token-value-12345'
      const hash1 = hashToken(rawToken)
      const hash2 = hashToken(rawToken)

      expect(hash1).toBe(hash2)
      expect(hash1.length).toBe(64)
      expect(hash1).not.toBe(rawToken)
    })
  })
})
