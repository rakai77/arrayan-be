import { describe, it, expect, vi } from 'vitest'
import { authenticate, authorize } from './auth.middleware.js'
import type { FastifyRequest, FastifyReply } from 'fastify'

describe('auth.middleware', () => {
  describe('authenticate', () => {
    it('harus mengembalikan 401 jika header Authorization dan cookie tidak ada', async () => {
      const request = {
        headers: {},
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
          message: expect.stringContaining('Token otentikasi tidak ditemukan'),
        }),
      )
    })

    it('harus mengisi userSession jika Authorization: Bearer token valid', async () => {
      const mockSession = {
        id: 'user-123',
        email: 'user@arrayan.com',
        role: { code: 'STAFF', name: 'Staff', permissions: [] },
      }

      const request = {
        headers: { authorization: 'Bearer valid-bearer-token' },
        cookies: {},
        server: {
          jwt: {
            verify: vi.fn().mockReturnValue(mockSession),
          },
        },
      } as unknown as FastifyRequest

      const reply = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as FastifyReply

      await authenticate(request, reply)

      expect(request.server.jwt.verify).toHaveBeenCalledWith('valid-bearer-token')
      expect(request.userSession).toEqual(mockSession)
    })

    it('harus mengisi userSession dari cookie jika header Authorization tidak ada', async () => {
      const mockSession = {
        id: 'user-123',
        email: 'user@arrayan.com',
        role: { code: 'STAFF', name: 'Staff', permissions: [] },
      }

      const request = {
        headers: {},
        cookies: { arrayan_access_token: 'valid-cookie-token' },
        server: {
          jwt: {
            verify: vi.fn().mockReturnValue(mockSession),
          },
        },
      } as unknown as FastifyRequest

      const reply = {
        status: vi.fn().mockReturnThis(),
        send: vi.fn(),
      } as unknown as FastifyReply

      await authenticate(request, reply)

      expect(request.server.jwt.verify).toHaveBeenCalledWith('valid-cookie-token')
      expect(request.userSession).toEqual(mockSession)
    })

    it('harus mengembalikan 401 jika token invalid atau kedaluwarsa', async () => {
      const request = {
        headers: { authorization: 'Bearer invalid-token' },
        cookies: {},
        server: {
          jwt: {
            verify: vi.fn().mockImplementation(() => {
              throw new Error('jwt expired')
            }),
          },
        },
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
          message: 'Token otentikasi tidak valid atau telah kedaluwarsa.',
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
