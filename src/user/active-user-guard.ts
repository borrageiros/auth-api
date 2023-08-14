// src/user/active-user.guard.ts
import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { UserService } from './user.service';

@Injectable()
export class ActiveUserGuard implements CanActivate {
    constructor(
        private userService: UserService
    ) { }

    async canActivate(
        context: ExecutionContext,
    ): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const user = await this.userService.findOneByUsername(request.user.username);

        if (!user.actived) {
            throw new ForbiddenException(['Your account is not activated.']);
        }

        return true;
    }
}
