// src/auth/auth.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from '../user/user.module';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';
import { MailService } from './mail.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/user/user.entity';

@Module({
    imports: [
        forwardRef(() => UserModule),
        JwtModule.register({
            secret: process.env.JWT_SECRET_KEY,
            signOptions: { expiresIn: process.env.JWT_TOKEN_SESSION_EXPIRE },
        }),
        TypeOrmModule.forFeature([User])
    ],
    providers: [ JwtStrategy, AuthService, MailService ],
    controllers: [ AuthController ],
    exports: [ AuthService, MailService ],
})
export class AuthModule { }
