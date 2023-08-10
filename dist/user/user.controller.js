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
const swagger_1 = require("@nestjs/swagger");
const passport_1 = require("@nestjs/passport");
const change_username_dto_1 = require("./dto/change-username.dto");
const auth_service_1 = require("../auth/auth.service");
const class_transformer_1 = require("class-transformer");
const public_user_info_dto_1 = require("./dto/public-user-info.dto");
let UserController = exports.UserController = class UserController {
    constructor(userService, authService) {
        this.userService = userService;
        this.authService = authService;
    }
    async getUserByUsername(username, res) {
        try {
            const user = await this.userService.findOneByUsername(username);
            return res.status(common_1.HttpStatus.OK).send((0, class_transformer_1.plainToClass)(public_user_info_dto_1.PublicUserInfo, user));
        }
        catch (error) {
            return res.status(common_1.HttpStatus.NOT_FOUND).send({ message: error.message });
        }
    }
    async getUserByToken(res, req) {
        const connectedUser = await this.userService.findUserById(req.user.id);
        return res.status(common_1.HttpStatus.OK).send(connectedUser);
    }
    async searchUsersByUsername(username, res) {
        let users = [];
        try {
            users = await this.userService.findUsersByEmail(username);
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
        const connectedUser = await this.userService.findUserById(req.user.id);
        const newUsername = changeUsernameDto.newUsername;
        if (!newUsername) {
            throw new common_1.BadRequestException(['A new username must be provided.']);
        }
        const token = await this.authService.validateUser(connectedUser.username, changeUsernameDto.password);
        if (!token) {
            throw new common_1.UnauthorizedException(['Incorrect password']);
        }
        try {
            await this.userService.changeUsernameConnectedUser(connectedUser.id, changeUsernameDto.newUsername);
        }
        catch (error) {
            if (error.sqlMessage.includes(changeUsernameDto.newUsername)) {
                throw new common_1.ConflictException(['Username already in use']);
            }
        }
        return res.status(common_1.HttpStatus.OK).send({ message: ['Username changed successfully'] });
    }
};
__decorate([
    (0, common_1.Get)(),
    (0, swagger_1.ApiOperation)({ summary: 'Get a specific user by username (Public Info)' }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'User public info (Object)' }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Not found' }),
    __param(0, (0, common_1.Query)('username')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "getUserByUsername", null);
__decorate([
    (0, common_1.Get)("/profile"),
    (0, swagger_1.ApiOperation)({ summary: 'Get user profile by connected user (Private/All Info)' }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'User all info (Object)' }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 401, description: 'Unauthorized' }),
    __param(0, (0, common_1.Res)()),
    __param(1, (0, common_1.Request)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "getUserByToken", null);
__decorate([
    (0, common_1.Get)('/search'),
    (0, swagger_1.ApiOperation)({ summary: 'Get users by username or email, case insensitive and use the function LIKE from mysql ' }),
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
    __param(0, (0, common_1.Query)('username')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "searchUsersByUsername", null);
__decorate([
    (0, common_1.Post)('/change-username'),
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
    (0, swagger_1.ApiResponse)({ status: 409, description: 'Conflict' }),
    __param(0, (0, common_1.Request)()),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, change_username_dto_1.ChangeUsernameDto, Object]),
    __metadata("design:returntype", Promise)
], UserController.prototype, "changeUsername", null);
exports.UserController = UserController = __decorate([
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
    (0, swagger_1.ApiTags)('Users'),
    (0, common_1.Controller)('/users'),
    __metadata("design:paramtypes", [user_service_1.UserService,
        auth_service_1.AuthService])
], UserController);
//# sourceMappingURL=user.controller.js.map