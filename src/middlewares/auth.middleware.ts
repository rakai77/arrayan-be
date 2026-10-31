import type { FastifyRequest, FastifyReply } from 'fastify'
import type { UserSessionPayload } from '../modules/auth/auth.schema.js'

declare module 'fastify' {
  interface FastifyRequest {
    userSession?: UserSessionPayload
  }
}

/**
 * Middleware untuk memverifikasi session JWT dari Cookie HttpOnly
 */
export async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  try {
    const token = request.cookies.arrayan_token

    if (!token) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Sesi tidak ditemukan atau telah kedaluwarsa. Silakan login kembali.',
      })
    }

    const decoded = await request.jwtVerify<UserSessionPayload>()
    request.userSession = decoded
  } catch {
    return reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Token otentikasi tidak valid.',
    })
  }
}

/**
 * Middleware untuk otorisasi berbasis Role (RBAC)
 */
export function authorize(allowedRoles: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const user = request.userSession

    if (!user) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Autentikasi diperlukan.',
      })
    }

    if (!allowedRoles.includes(user.role.code)) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Anda tidak memiliki hak akses untuk tindakan ini.',
      })
    }
  }
}
