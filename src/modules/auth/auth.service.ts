import bcrypt from 'bcrypt'
import { prisma } from '../../lib/prisma.js'
import type { LoginInput, UserSessionPayload } from './auth.schema.js'

export const authService = {
  async validateUser(input: LoginInput): Promise<UserSessionPayload> {
    const user = await prisma.user.findUnique({
      where: { email: input.email.toLowerCase().trim() },
      include: {
        role: true,
        employee: true,
      },
    })

    if (!user) {
      throw new Error('Email atau password salah')
    }

    if (!user.isActive) {
      throw new Error('Akun dinonaktifkan. Hubungi HR Administrator')
    }

    const isValidPassword = await bcrypt.compare(input.password, user.passwordHash)
    if (!isValidPassword) {
      throw new Error('Email atau password salah')
    }

    // Update timestamp last login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    })

    return {
      id: user.id,
      email: user.email,
      role: {
        code: user.role.code,
        name: user.role.name,
        permissions: (user.role.permissions as string[]) || [],
      },
      employee: user.employee
        ? {
            id: user.employee.id,
            nik: user.employee.nik,
            fullName: user.employee.fullName,
            jobTitle: user.employee.jobTitle,
            department: user.employee.department,
            managerId: user.employee.managerId,
          }
        : null,
    }
  },

  async getUserProfile(userId: string): Promise<UserSessionPayload> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        role: true,
        employee: true,
      },
    })

    if (!user || !user.isActive) {
      throw new Error('User tidak ditemukan atau tidak aktif')
    }

    return {
      id: user.id,
      email: user.email,
      role: {
        code: user.role.code,
        name: user.role.name,
        permissions: (user.role.permissions as string[]) || [],
      },
      employee: user.employee
        ? {
            id: user.employee.id,
            nik: user.employee.nik,
            fullName: user.employee.fullName,
            jobTitle: user.employee.jobTitle,
            department: user.employee.department,
            managerId: user.employee.managerId,
          }
        : null,
    }
  },
}
