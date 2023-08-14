// src/auth/auth.service.ts
import { HttpStatus, Injectable, Res, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UserService } from '../user/user.service';
import { User } from 'src/user/user.entity';
import { isEmail } from 'class-validator';

@Injectable()
export class AuthService {
    constructor(
        private userService: UserService,
        private jwtService: JwtService,
    ) { }

    generateResetToken(user: User): string {
        const payload = {
            sub: user.id,
            username: user.username,
            isPasswordReset: true 
        };
        
        return this.jwtService.sign(payload, {
            expiresIn: process.env.JWT_TOKEN_PASSWORD_RECOVERY_EXPIRE
        });
    }

    async validateUser(usernameOrEmail: string, password: string, @Res() res): Promise<any> {
        let user = new User;
        
        if ( isEmail(usernameOrEmail) ) {
            // Try find by email
            user = await this.userService.findOneByEmail(usernameOrEmail);
        } else {
            // Try find by username
            user = await this.userService.findOneByUsername(usernameOrEmail);
        }

        if (!user){
            return res.status(HttpStatus.NOT_FOUND).send({ message: ['User not found'] });
        }

        // Check password
        if (user && await bcrypt.compare(password, user.password)) {
            return user;
        }
        return null;
    }

    async login(usernameOrEmail: string, password: string, @Res() res) {
        const user = await this.validateUser(usernameOrEmail, password, res);

        if (!user) {
            throw new UnauthorizedException(['Incorrect password']);
        }
        const payload = { username: user.username, sub: user.id };
        return {
            access_token: this.jwtService.sign(payload),
        };
    }
}
