import { CanActivate, ExecutionContext } from '@nestjs/common';
import { UserService } from './user.service';
export declare class ActiveUserGuard implements CanActivate {
    private userService;
    constructor(userService: UserService);
    canActivate(context: ExecutionContext): Promise<boolean>;
}
