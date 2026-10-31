import type { FastifyPluginAsync } from 'fastify'
import { authService } from './auth.service.js'
import { loginSchema } from './auth.schema.js'
import { authenticate } from '../../middlewares/auth.middleware.js'

export const authRoutes: FastifyPluginAsync = async (fastify) => {
  // 1. Endpoint Login (Set HttpOnly Cookie)
  fastify.post('/login', {
    schema: {
      description: 'Login pengguna dan set HttpOnly session cookie (arrayan_token)',
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

        // Generate JWT Token (berlaku 24 jam)
        const token = fastify.jwt.sign(sessionPayload, { expiresIn: '24h' })

        const isProduction = process.env.NODE_ENV === 'production'

        // Set HttpOnly Cookie yang aman
        reply.setCookie('arrayan_token', token, {
          path: '/',
          httpOnly: true,
          secure: isProduction, // HTTPS di production
          sameSite: isProduction ? 'none' : 'lax',
          maxAge: 60 * 60 * 24, // 24 jam
        })

        return reply.send({
          statusCode: 200,
          message: 'Login berhasil',
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

  // 2. Endpoint Logout (Hapus Cookie)
  fastify.post('/logout', {
    schema: {
      description: 'Logout dan hapus session cookie',
      tags: ['Auth'],
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
    handler: async (_request, reply) => {
      reply.clearCookie('arrayan_token', { path: '/' })
      return reply.send({
        statusCode: 200,
        message: 'Logout berhasil',
      })
    },
  })

  // 3. Endpoint Me (Ambil info user login saat ini)
  fastify.get('/me', {
    preHandler: [authenticate],
    schema: {
      description: 'Mendapatkan data profil user aktif dari cookie HttpOnly',
      tags: ['Auth'],
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
