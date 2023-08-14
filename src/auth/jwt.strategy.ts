// src/auth/jwt.strategy.ts
import { Injectable, ParseUUIDPipe } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from './auth.service';
import jwt_decode from "jwt-decode";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor(private authService: AuthService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: process.env.JWT_SECRET_KEY,
        });
    }

    async validate(payload: any) {
        return { userId: payload.sub, username: payload.username, isPasswordReset: payload.isPasswordReset };
    }

    async decode(jwtToken: string) {
        return jwt_decode(jwtToken);
    }
    
}