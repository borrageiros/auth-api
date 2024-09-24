// src/auth/auth.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { UserModule } from '../user/user.module';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { MailService } from './mail.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/user/user.entity';
import { LoginController } from './controllers/login.controller';
import { RegisterController } from './controllers/register.controller';
import { ActivateAccountController } from './controllers/activateAccount.controller';
import { ForgotPasswordController } from './controllers/forgotPassword.controller';
import { ResetPasswordController } from './controllers/resetPassword.controller';
import { VerifyEmailController } from './controllers/verifyEmail.controller';

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
    controllers: [
        LoginController,
        RegisterController,
        VerifyEmailController,
        ActivateAccountController,
        ForgotPasswordController,
        ResetPasswordController,
    ],
    exports: [ AuthService, MailService ],
})
export class AuthModule { }
