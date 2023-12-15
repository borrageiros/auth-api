// src/user/user.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  imports: [
    forwardRef(() => AuthModule),
    TypeOrmModule.forFeature([User])
  ],
  providers: [UserService],
  controllers: [UserController],
  exports: [UserService], 
})
export class UserModule {}