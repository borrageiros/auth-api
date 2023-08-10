// src/auth/auth.service.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from '../user/user.service';
import { User } from 'src/user/user.entity';

@Injectable()
export class AuthService {
    constructor(
        private userService: UserService,
        private jwtService: JwtService,
    ) { }

    async validateUser(usernameOrEmail: string, password: string): Promise<any> {
        let user = new User;

        try{
            // Try find by username
            user = await this.userService.findOneByUsername(usernameOrEmail);
        }catch{
            // Try find by email
            user = await this.userService.findOneByEmail(usernameOrEmail);
        }
        
        if (user && await bcrypt.compare(password, user.password)) { // Check password
            const { password, ...result } = user;
            return result;
        }
        return null;
    }

    async login(usernameOrEmail: string, password: string) {
        const user = await this.validateUser(usernameOrEmail, password);
        if (!user) {
            throw new UnauthorizedException(['Incorrect password']);
        }
        const payload = { username: user.username, sub: user.id };
        return {
            access_token: this.jwtService.sign(payload),
        };
    }
}
