// src/auth/auth.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from '../user/user.module';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';

@Module({
    imports: [
        forwardRef(() => UserModule),
        JwtModule.register({
            secret: process.env.JWT_SECRET,
            signOptions: { expiresIn: process.env.JWT_TOKEN_SESSION_EXPIRE },
        }),
    ],
    providers: [JwtStrategy, AuthService],
    controllers: [AuthController],
    exports: [AuthService],
})
export class AuthModule { }
