/** Role-based access helpers. Roles are ordered by privilege. */

import type { Role } from '../store/types.js';

const RANK: Record<Role, number> = { VIEWER: 0, MEMBER: 1, ADMIN: 2, OWNER: 3 };

/** True if `role` is at least as privileged as `required`. */
export function roleAtLeast(role: Role, required: Role): boolean {
  return RANK[role] >= RANK[required];
}

export const CAN = {
  /** Create/verify projects, run scans. */
  manageProjects: (role: Role) => roleAtLeast(role, 'MEMBER'),
  /** Invite members, create teams. */
  manageOrg: (role: Role) => roleAtLeast(role, 'ADMIN'),
  /** Read scans/reports. */
  read: (_role: Role) => true,
};
