"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserController = void 0;
const common_1 = require("@nestjs/common");
const user_service_1 = require("./user.service");
const user_entity_1 = require("./user.entity");
const swagger_1 = require("@nestjs/swagger");
const passport_1 = require("@nestjs/passport");
const change_username_dto_1 = require("./dto/change-username.dto");
const auth_service_1 = require("../auth/auth.service");
const class_transformer_1 = require("class-transformer");
const change_email_dto_1 = require("./dto/change-email.dto");
const change_role_dto_1 = require("./dto/change-role.dto");
const active_user_guard_1 = require("./active-user-guard");
const mail_service_1 = require("../auth/mail.service");
let UserController = exports.UserController = class UserController {
    constructor(userService, authService, mailService) {
        this.userService = userService;
        this.authService = authService;
        this.mailService = mailService;
    }
    async getUserByUsername(res, username) {
        try {
            if (username) {
                const user = await this.userService.findOneByUsername(username);
                return res.status(common_1.HttpStatus.OK).send((0, class_transformer_1.plainToClass)(user_entity_1.PublicUserInfo, user));
            }
            else {
                const users = await this.userService.findAllUsers();
                return res.status(common_1.HttpStatus.OK).send({ users: (0, class_transformer_1.plainToClass)(user_entity_1.PublicUserInfo, users) });
            }
        }
        catch (error) {
            return res.status(common_1.HttpStatus.NOT_FOUND).send({ message: error.message });
        }
    }
    async getUserByToken(res, req) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        return res.status(common_1.HttpStatus.OK).send(connectedUser);
    }
    async delete(res, req) {
        const result = await this.userService.deleteOneById(req.user.userId);
        return res.status(common_1.HttpStatus.OK).send({ message: "User deleted successfully" });
    }
    async searchUsersByUsername(res, username, email) {
        let users = [];
        try {
            users = await this.userService.findUsersByEmail(email);
            return res.status(common_1.HttpStatus.OK).send(users);
        }
        catch {
            try {
                users = await this.userService.findUsersByUsername(username);
            }
            catch (error) {
                return res.status(common_1.HttpStatus.NOT_FOUND).send({ message: error.message });
            }
            return res.status(common_1.HttpStatus.OK).send(users);
        }
    }
    async changeUsername(req, changeUsernameDto, res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        const newUsername = changeUsernameDto.newUsername;
        if (!newUsername) {
            throw new common_1.BadRequestException(['A new username must be provided.']);
        }
        const user = await this.authService.validateUser(connectedUser.username, changeUsernameDto.password, res);
        if (!user) {
            throw new common_1.UnauthorizedException(['Incorrect password']);
        }
        try {
            await this.userService.changeUsername(connectedUser.id, changeUsernameDto.newUsername);
        }
        catch (error) {
            if (error.sqlMessage.includes(changeUsernameDto.newUsername)) {
                throw new common_1.ConflictException(['Username already in use']);
            }
        }
        return res.status(common_1.HttpStatus.OK).send({ message: ['Username changed successfully'] });
    }
    async changeEmail(req, changeEmailDto, res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        const user = await this.authService.validateUser(connectedUser.username, changeEmailDto.password, res);
        if (!user) {
            throw new common_1.UnauthorizedException(['Incorrect password']);
        }
        try {
            await this.userService.changeEmail(connectedUser.id, changeEmailDto.newEmail);
        }
        catch (error) {
            if (error.sqlMessage.includes(changeEmailDto.newEmail)) {
                throw new common_1.ConflictException(['Email already in use']);
            }
        }
        return res.status(common_1.HttpStatus.OK).send({ message: ['Email changed successfully'] });
    }
    async changeRole(req, changeRoleDto, res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        let userToChange;
        try {
            if (!isNaN(Number(changeRoleDto.userOrIdToChange))) {
                userToChange = await this.userService.findOneById(Number(changeRoleDto.userOrIdToChange));
            }
            else {
                userToChange = await this.userService.findOneByUsername(changeRoleDto.userOrIdToChange);
            }
        }
        catch (error) {
            return res.status(common_1.HttpStatus.NOT_FOUND).send({ message: ['User not found'] });
        }
        switch (connectedUser.role) {
            case user_entity_1.UserRole.ROOT:
                userToChange.role = changeRoleDto.newRole;
                break;
            case user_entity_1.UserRole.ADMIN:
                if (userToChange.role !== user_entity_1.UserRole.ROOT) {
                    userToChange.role = changeRoleDto.newRole;
                }
                else {
                    return res.status(common_1.HttpStatus.FORBIDDEN).send({ message: ["Admins cannot change the role of a root user"] });
                }
                break;
            case user_entity_1.UserRole.USER:
                return res.status(common_1.HttpStatus.FORBIDDEN).send({ message: ['You do not have permission to perform this action'] });
        }
        await this.userService.changeRole(userToChange.id, changeRoleDto.newRole);
        return res.status(common_1.HttpStatus.OK).send({ message: ['Role updated to ' + userToChange.role + ' for ' + userToChange.username] });
    }
};
__decorate([
    (0, common_1.Get)(),
    (0, swagger_1.ApiTags)('User'),
    (0, swagger_1.ApiOperation)({ summary: 'Get a specific user by username or all users if no username provided (Public Info)' }),
    (0, swagger_1.ApiQuery)({ name: "username", description: "The username to search for.", type: String, required: false }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'User public info (Object or Array)' }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Not found' }),
    __param(0, (0, common_1.Res)()),
    __param(1, (0, common_1.Query)('username')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, String]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "getUserByUsername", null);
__decorate([
    (0, common_1.Get)("/profile"),
    (0, swagger_1.ApiTags)('User'),
    (0, swagger_1.ApiOperation)({ summary: 'Get user profile by connected user (Private/All Info)' }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'User all info (Object)' }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Not found' }),
    __param(0, (0, common_1.Res)()),
    __param(1, (0, common_1.Request)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "getUserByToken", null);
__decorate([
    (0, common_1.Delete)('/profile'),
    (0, swagger_1.ApiTags)('User'),
    (0, swagger_1.ApiOperation)({ summary: 'Delete user account' }),
    (0, swagger_1.ApiOkResponse)({
        description: 'User deleted successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'User deleted successfully'
                    }
                }
            }
        }
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Not found' }),
    __param(0, (0, common_1.Res)()),
    __param(1, (0, common_1.Request)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "delete", null);
__decorate([
    (0, common_1.Get)('/search'),
    (0, swagger_1.ApiTags)('User'),
    (0, swagger_1.ApiOperation)({ summary: 'Get a list of users by username or email, case insensitive and use the function LIKE from mysql ' }),
    (0, swagger_1.ApiOkResponse)({
        description: 'List of usernames matching the search term',
        schema: {
            type: 'object',
            properties: {
                users: {
                    type: 'array',
                    items: {
                        type: 'string'
                    },
                    example: ["user1", "user2", "user3"]
                }
            }
        }
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Not found' }),
    (0, swagger_1.ApiQuery)({ name: "username", description: "The username to search for.", type: String, required: false }),
    (0, swagger_1.ApiQuery)({ name: "email", description: "The email to search for.", type: String, required: false }),
    __param(0, (0, common_1.Res)()),
    __param(1, (0, common_1.Query)('username')),
    __param(2, (0, common_1.Query)('email')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, String, String]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "searchUsersByUsername", null);
__decorate([
    (0, common_1.Patch)('/change-username'),
    (0, swagger_1.ApiTags)('User'),
    (0, swagger_1.ApiOperation)({ summary: 'Change username' }),
    (0, swagger_1.ApiOkResponse)({
        description: 'Username changed successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Username changed successfully'
                    }
                }
            }
        }
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Not found' }),
    (0, swagger_1.ApiResponse)({ status: 409, description: 'Conflict' }),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, change_username_dto_1.ChangeUsernameDto, Object]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "changeUsername", null);
__decorate([
    (0, common_1.Patch)('/change-email'),
    (0, swagger_1.ApiTags)('User'),
    (0, swagger_1.ApiOperation)({ summary: 'Change email' }),
    (0, swagger_1.ApiOkResponse)({
        description: 'Email changed successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Email changed successfully'
                    }
                }
            }
        }
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Not found' }),
    (0, swagger_1.ApiResponse)({ status: 409, description: 'Conflict' }),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, change_email_dto_1.ChangeEmailDto, Object]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "changeEmail", null);
__decorate([
    (0, common_1.Patch)('/admin/change-role'),
    (0, swagger_1.ApiTags)('Admin'),
    (0, swagger_1.ApiOperation)({ summary: 'Change a user role' }),
    (0, swagger_1.ApiOkResponse)({
        description: 'Role updated to {role} for {user}',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Role updated to {role} for {user}'
                    }
                }
            }
        }
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    (0, swagger_1.ApiResponse)({ status: 403, description: 'Forbidden' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Not found' }),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, change_role_dto_1.ChangeRoleDto, Object]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "changeRole", null);
exports.UserController = UserController = __decorate([
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt'), active_user_guard_1.ActiveUserGuard),
    (0, swagger_1.ApiBearerAuth)(),
    (0, common_1.Controller)('/users'),
    __metadata("design:paramtypes", [user_service_1.UserService,
        auth_service_1.AuthService,
        mail_service_1.MailService])
], UserController);
//# sourceMappingURL=user.controller.js.map