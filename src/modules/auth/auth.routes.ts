import type { FastifyPluginAsync } from 'fastify'
import { authService } from './auth.service.js'
import { loginSchema, refreshSchema } from './auth.schema.js'
import { authenticate } from '../../middlewares/auth.middleware.js'

const ACCESS_TOKEN_EXPIRY = '15m'
const ACCESS_TOKEN_MAX_AGE = 15 * 60 // 15 menit
const REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60 // 7 hari

export const authRoutes: FastifyPluginAsync = async (fastify) => {
  // 1. Endpoint Login (Mengembalikan accessToken, refreshToken, dan Set HttpOnly Cookies)
  fastify.post('/login', {
    schema: {
      description: 'Login pengguna, menghasilkan access token (15m) & refresh token (7d), serta menyetel HttpOnly cookies',
      tags: ['Auth'],
      body: {
        type: 'object',
        required: ['email', 'password'],
        properties: {
          email: { type: 'string', format: 'email', examples: ['superadmin@arrayan.com'] },
          password: { type: 'string', minLength: 6, examples: ['Password123!'] },
        },
      },
      response: {
        200: {
          description: 'Login berhasil',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            message: { type: 'string' },
            accessToken: { type: 'string' },
            refreshToken: { type: 'string' },
            user: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                email: { type: 'string' },
                role: {
                  type: 'object',
                  properties: {
                    code: { type: 'string' },
                    name: { type: 'string' },
                    permissions: { type: 'array', items: { type: 'string' } },
                  },
                },
                employee: {
                  type: 'object',
                  nullable: true,
                  properties: {
                    id: { type: 'string' },
                    nik: { type: 'string' },
                    fullName: { type: 'string' },
                    jobTitle: { type: 'string' },
                    department: { type: 'string', nullable: true },
                    managerId: { type: 'string', nullable: true },
                  },
                },
              },
            },
          },
        },
        400: {
          description: 'Bad Request / Format input salah',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            error: { type: 'string' },
            message: { type: 'string' },
          },
        },
        401: {
          description: 'Unauthorized / Kredensial salah',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            error: { type: 'string' },
            message: { type: 'string' },
          },
        },
      },
    },
    handler: async (request, reply) => {
      const parseResult = loginSchema.safeParse(request.body)
      if (!parseResult.success) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: parseResult.error.issues[0]?.message || 'Input tidak valid',
        })
      }

      try {
        const sessionPayload = await authService.validateUser(parseResult.data)

        // 1. Generate Access Token JWT (15 menit)
        const accessToken = fastify.jwt.sign(sessionPayload, { expiresIn: ACCESS_TOKEN_EXPIRY })

        // 2. Generate Refresh Token Opaque (7 hari) & Simpan di Database
        const refreshToken = await authService.createRefreshToken(sessionPayload.id)

        const isProduction = process.env.NODE_ENV === 'production'

        // Set HttpOnly Cookies untuk Web Client
        reply.setCookie('arrayan_access_token', accessToken, {
          path: '/',
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? 'none' : 'lax',
          maxAge: ACCESS_TOKEN_MAX_AGE,
        })

        reply.setCookie('arrayan_token', accessToken, {
          path: '/',
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? 'none' : 'lax',
          maxAge: ACCESS_TOKEN_MAX_AGE,
        })

        reply.setCookie('arrayan_refresh_token', refreshToken, {
          path: '/api/auth',
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? 'none' : 'lax',
          maxAge: REFRESH_TOKEN_MAX_AGE,
        })

        return reply.send({
          statusCode: 200,
          message: 'Login berhasil',
          accessToken,
          refreshToken,
          user: sessionPayload,
        })
      } catch (err: unknown) {
        const error = err as Error
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: error.message || 'Email atau password salah',
        })
      }
    },
  })

  // 2. Endpoint Refresh Token (Memperbarui accessToken menggunakan refreshToken)
  fastify.post('/refresh', {
    schema: {
      description: 'Memperbarui access token dengan refresh token (mendukung Token Rotation)',
      tags: ['Auth'],
      body: {
        type: 'object',
        properties: {
          refreshToken: { type: 'string', description: 'Opsional jika token tersedia di cookie HttpOnly' },
        },
      },
      response: {
        200: {
          description: 'Token berhasil diperbarui',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            message: { type: 'string' },
            accessToken: { type: 'string' },
            refreshToken: { type: 'string' },
            user: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                email: { type: 'string' },
                role: {
                  type: 'object',
                  properties: {
                    code: { type: 'string' },
                    name: { type: 'string' },
                    permissions: { type: 'array', items: { type: 'string' } },
                  },
                },
                employee: {
                  type: 'object',
                  nullable: true,
                  properties: {
                    id: { type: 'string' },
                    nik: { type: 'string' },
                    fullName: { type: 'string' },
                    jobTitle: { type: 'string' },
                    department: { type: 'string', nullable: true },
                    managerId: { type: 'string', nullable: true },
                  },
                },
              },
            },
          },
        },
        400: {
          description: 'Bad Request / Refresh token tidak disediakan',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            error: { type: 'string' },
            message: { type: 'string' },
          },
        },
        401: {
          description: 'Unauthorized / Refresh token tidak valid atau expired',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            error: { type: 'string' },
            message: { type: 'string' },
          },
        },
      },
    },
    handler: async (request, reply) => {
      const parseResult = refreshSchema.safeParse(request.body)
      const rawBodyToken = parseResult.success ? parseResult.data.refreshToken : undefined
      const token = rawBodyToken || request.cookies.arrayan_refresh_token

      if (!token) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: 'Refresh token tidak ditemukan di body request maupun cookie.',
        })
      }

      try {
        const { user, newRefreshToken } = await authService.rotateRefreshToken(token)

        const newAccessToken = fastify.jwt.sign(user, { expiresIn: ACCESS_TOKEN_EXPIRY })
        const isProduction = process.env.NODE_ENV === 'production'

        // Perbarui cookies
        reply.setCookie('arrayan_access_token', newAccessToken, {
          path: '/',
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? 'none' : 'lax',
          maxAge: ACCESS_TOKEN_MAX_AGE,
        })

        reply.setCookie('arrayan_token', newAccessToken, {
          path: '/',
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? 'none' : 'lax',
          maxAge: ACCESS_TOKEN_MAX_AGE,
        })

        reply.setCookie('arrayan_refresh_token', newRefreshToken, {
          path: '/api/auth',
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? 'none' : 'lax',
          maxAge: REFRESH_TOKEN_MAX_AGE,
        })

        return reply.send({
          statusCode: 200,
          message: 'Token berhasil diperbarui',
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
          user,
        })
      } catch (err: unknown) {
        const error = err as Error
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: error.message || 'Refresh token tidak valid atau telah kedaluwarsa',
        })
      }
    },
  })

  // 3. Endpoint Logout (Hapus Cookies & Revoke Refresh Token di Database)
  fastify.post('/logout', {
    schema: {
      description: 'Logout pengguna, membatalkan refresh token di database dan menghapus cookies sesi',
      tags: ['Auth'],
      body: {
        type: 'object',
        properties: {
          refreshToken: { type: 'string', description: 'Opsional jika token tersedia di cookie HttpOnly' },
        },
      },
      response: {
        200: {
          description: 'Logout berhasil',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            message: { type: 'string' },
          },
        },
      },
    },
    handler: async (request, reply) => {
      const parseResult = refreshSchema.safeParse(request.body)
      const rawBodyToken = parseResult.success ? parseResult.data.refreshToken : undefined
      const token = rawBodyToken || request.cookies.arrayan_refresh_token

      if (token) {
        try {
          await authService.revokeRefreshToken(token)
        } catch {
          // Abaikan error revoke saat logout agar cookie tetap dibersihkan
        }
      }

      reply.clearCookie('arrayan_access_token', { path: '/' })
      reply.clearCookie('arrayan_token', { path: '/' })
      reply.clearCookie('arrayan_refresh_token', { path: '/api/auth' })

      return reply.send({
        statusCode: 200,
        message: 'Logout berhasil',
      })
    },
  })

  // 4. Endpoint Me (Mendapatkan data user aktif dari Bearer token atau Cookie)
  fastify.get('/me', {
    preHandler: [authenticate],
    schema: {
      description: 'Mendapatkan data profil user aktif dari Bearer token atau cookie HttpOnly',
      tags: ['Auth'],
      security: [{ bearerAuth: [] }],
      response: {
        200: {
          description: 'Data profil user aktif',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            user: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                email: { type: 'string' },
                role: {
                  type: 'object',
                  properties: {
                    code: { type: 'string' },
                    name: { type: 'string' },
                    permissions: { type: 'array', items: { type: 'string' } },
                  },
                },
                employee: {
                  type: 'object',
                  nullable: true,
                  properties: {
                    id: { type: 'string' },
                    nik: { type: 'string' },
                    fullName: { type: 'string' },
                    jobTitle: { type: 'string' },
                    department: { type: 'string', nullable: true },
                    managerId: { type: 'string', nullable: true },
                  },
                },
              },
            },
          },
        },
        401: {
          description: 'Unauthorized / Sesi tidak ditemukan',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            error: { type: 'string' },
            message: { type: 'string' },
          },
        },
        404: {
          description: 'Not Found / User tidak ditemukan',
          type: 'object',
          properties: {
            statusCode: { type: 'number' },
            error: { type: 'string' },
            message: { type: 'string' },
          },
        },
      },
    },
    handler: async (request, reply) => {
      try {
        const profile = await authService.getUserProfile(request.userSession!.id)
        return reply.send({
          statusCode: 200,
          user: profile,
        })
      } catch (err: unknown) {
        const error = err as Error
        return reply.status(404).send({
          statusCode: 404,
          error: 'Not Found',
          message: error.message,
        })
      }
    },
  })
}
