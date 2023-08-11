import { UserRole } from '../user.entity';
export declare class ChangeRoleDto {
    userOrIdToChange: string;
    newRole: UserRole;
}
