// src/user/user.module.ts
import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';
import { UserService } from './user.service';
import { AuthModule } from 'src/auth/auth.module';
import { GetUserController } from './controllers/user/getUser.controller';
import { GetProfileController } from './controllers/user/getProfile.controller';
import { DeleteUserController } from './controllers/user/deleteUser.controller';
import { GetUsersController } from './controllers/user/getUsers.controller';
import { ChangeUsernameController } from './controllers/user/changeUsername.controller';
import { ChangeEmailController } from './controllers/user/changeEmail.controller';
import { ChangePasswordController } from './controllers/user/changePassword.controller';
import { ChangeRoleController } from './controllers/admin/changeRoleAdmin.controller';
import { ChangePasswordAdminController } from './controllers/admin/changePasswordAdmin.controller';
import { ChangeEmailAdminController } from './controllers/admin/changeEmailAdmin.controller';
import { ChangeUsernameAdminController } from './controllers/admin/changeUsernameAdmin.controller';
import { DeleteUserAdminController } from './controllers/admin/deleteUserAdmin.controller';

@Module({
  imports: [
    forwardRef(() => AuthModule),
    TypeOrmModule.forFeature([User])
  ],
  providers: [UserService],
  controllers: [
    GetUserController,
    GetUsersController,
    GetProfileController,
    DeleteUserController,
    ChangeUsernameController,
    ChangeEmailController,
    ChangePasswordController,
    ChangeUsernameAdminController,
    ChangeEmailAdminController,
    ChangePasswordAdminController,
    ChangeRoleController,
    DeleteUserAdminController,
  ],
  exports: [UserService], 
})
export class UserModule {}