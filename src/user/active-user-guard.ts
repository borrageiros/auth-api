// src/user/active-user.guard.ts
import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { UserService } from './user.service';
import { isEmail } from 'class-validator';
import { User } from './user.entity';

@Injectable()
export class ActiveUserGuard implements CanActivate {
    constructor(
        private userService: UserService
    ) { }

    async canActivate(
        context: ExecutionContext,
    ): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        let user = new User;
        
        if (request.route.path){
            if ( isEmail(request.body.usernameOrEmail) ) {
                // Try find by email
                user = await this.userService.findOneByEmail(request.body.usernameOrEmail);
            } else {
                // Try find by username
                user = await this.userService.findOneByUsername(request.body.usernameOrEmail);
            }
        }else{
            user = await this.userService.findOneByUsername(request.user.username);
        }

        if (!user.actived) {
            throw new ForbiddenException(['Your account is not activated.']);
        }

        return true;
    }
}
