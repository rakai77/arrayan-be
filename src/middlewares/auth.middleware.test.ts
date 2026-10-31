import { describe, it, expect, vi } from 'vitest'
import { authenticate, authorize } from './auth.middleware.js'
import type { FastifyRequest, FastifyReply } from 'fastify'

describe('auth.middleware', () => {
  describe('authenticate', () => {
    it('harus mengembalikan 401 jika cookie arrayan_token tidak ada', async () => {
      const request = {
        cookies: {},
      } as unknown as FastifyRequest

      const statusMock = vi.fn().mockReturnThis()
      const sendMock = vi.fn()
      const reply = {
        status: statusMock,
        send: sendMock,
      } as unknown as FastifyReply

      await authenticate(request, reply)

      expect(statusMock).toHaveBeenCalledWith(401)
      expect(sendMock).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Unauthorized',
        }),
      )
    })

    it('harus mengisi userSession jika jwtVerify berhasil', async () => {
      const mockSession = {
        id: 'user-123',
        email: 'user@arrayan.com',
        role: { code: 'STAFF', name: 'Staff', permissions: [] },
      }

      const request = {
        cookies: { arrayan_token: 'valid-jwt-token' },
        jwtVerify: vi.fn().mockResolvedValue(mockSession),
      } as unknown as FastifyRequest

      const reply = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as FastifyReply

      await authenticate(request, reply)

      expect(request.userSession).toEqual(mockSession)
    })

    it('harus mengembalikan 401 jika jwtVerify gagal / token invalid', async () => {
      const request = {
        cookies: { arrayan_token: 'invalid-jwt-token' },
        jwtVerify: vi.fn().mockRejectedValue(new Error('Invalid token')),
      } as unknown as FastifyRequest

      const statusMock = vi.fn().mockReturnThis()
      const sendMock = vi.fn()
      const reply = {
        status: statusMock,
        send: sendMock,
      } as unknown as FastifyReply

      await authenticate(request, reply)

      expect(statusMock).toHaveBeenCalledWith(401)
      expect(sendMock).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Token otentikasi tidak valid.',
        }),
      )
    })
  })

  describe('authorize', () => {
    it('harus mengembalikan 401 jika userSession tidak ditemukan', async () => {
      const request = {} as unknown as FastifyRequest
      const statusMock = vi.fn().mockReturnThis()
      const sendMock = vi.fn()
      const reply = {
        status: statusMock,
        send: sendMock,
      } as unknown as FastifyReply

      const guard = authorize(['SUPER_ADMIN'])
      await guard(request, reply)

      expect(statusMock).toHaveBeenCalledWith(401)
    })

    it('harus mengembalikan 403 jika role user tidak termasuk dalam allowedRoles', async () => {
      const request = {
        userSession: {
          id: 'user-123',
          email: 'staff@arrayan.com',
          role: { code: 'STAFF', name: 'Staff', permissions: [] },
        },
      } as unknown as FastifyRequest

      const statusMock = vi.fn().mockReturnThis()
      const sendMock = vi.fn()
      const reply = {
        status: statusMock,
        send: sendMock,
      } as unknown as FastifyReply

      const guard = authorize(['SUPER_ADMIN', 'HR_GA'])
      await guard(request, reply)

      expect(statusMock).toHaveBeenCalledWith(403)
      expect(sendMock).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Forbidden',
        }),
      )
    })

    it('harus mengizinkan request jika role user termasuk dalam allowedRoles', async () => {
      const request = {
        userSession: {
          id: 'user-admin',
          email: 'admin@arrayan.com',
          role: { code: 'SUPER_ADMIN', name: 'Super Admin', permissions: ['all'] },
        },
      } as unknown as FastifyRequest

      const statusMock = vi.fn().mockReturnThis()
      const sendMock = vi.fn()
      const reply = {
        status: statusMock,
        send: sendMock,
      } as unknown as FastifyReply

      const guard = authorize(['SUPER_ADMIN', 'HR_GA'])
      await guard(request, reply)

      expect(statusMock).not.toHaveBeenCalled()
      expect(sendMock).not.toHaveBeenCalled()
    })
  })
})
