import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'

const prisma = new PrismaClient()

const DEFAULT_ROLES = [
  {
    code: 'SUPER_ADMIN',
    name: 'Super Admin / HR GA',
    description: 'Akses penuh ke seluruh modul, pengaturan sistem, kelola data karyawan',
    permissions: ['all'],
  },
  {
    code: 'MANAGEMENT',
    name: 'Management',
    description: 'Top Hierarchy. Read-only across all divisions & approval cuti',
    permissions: ['leave.approve', 'company.read_all'],
  },
  {
    code: 'SR_MANAGER',
    name: 'Senior Manager',
    description: 'Kelola divisi utama, approval izin/cuti bawahan, review KPI divisi',
    permissions: ['leave.approve', 'kpi.review'],
  },
  {
    code: 'MANAGER',
    name: 'Manager',
    description: 'Kelola sub-divisi/tim bawahan, approval izin/cuti bawahan, review KPI tim',
    permissions: ['leave.approve', 'kpi.review'],
  },
  {
    code: 'SUPERVISOR',
    name: 'Supervisor',
    description: 'Mengawasi staf langsung, approval izin/cuti bawahan, evaluasi kinerja tim',
    permissions: ['leave.approve', 'kpi.evaluate'],
  },
  {
    code: 'STAFF',
    name: 'Staff / Karyawan',
    description: 'Pengajuan cuti/izin/reimburse, jadwal training pribadi, cek kuota',
    permissions: ['leave.create', 'reimburse.create', 'profile.read'],
  },
]

async function main() {
  console.log('🌱 Starting database seeding...')

  // 1. Seed Roles
  console.log('Inserting default roles...')
  for (const role of DEFAULT_ROLES) {
    await prisma.role.upsert({
      where: { code: role.code },
      update: { name: role.name, description: role.description, permissions: role.permissions },
      create: {
        code: role.code,
        name: role.name,
        description: role.description,
        permissions: role.permissions,
      },
    })
  }

  // 2. Seed Default Super Admin Account
  const superAdminRole = await prisma.role.findUniqueOrThrow({
    where: { code: 'SUPER_ADMIN' },
  })

  const adminEmail = 'superadmin@arrayan.com'
  const defaultPassword = 'Password123!'
  const passwordHash = await bcrypt.hash(defaultPassword, 10)

  const adminUser = await prisma.user.upsert({
    where: { email: adminEmail },
    update: {},
    create: {
      email: adminEmail,
      passwordHash,
      roleId: superAdminRole.id,
      employee: {
        create: {
          nik: 'ADM-001',
          fullName: 'Super Administrator HR',
          jobTitle: 'HR & System Admin',
          department: 'HR GA',
          employmentType: 'KARTAP',
        },
      },
    },
    include: { employee: true },
  })

  console.log('✅ Seeding completed!')
  console.log('----------------------------------------------------')
  console.log(`Default Super Admin Email    : ${adminUser.email}`)
  console.log(`Default Super Admin Password : ${defaultPassword}`)
  console.log('----------------------------------------------------')
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })

