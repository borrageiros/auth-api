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
let UserController = exports.UserController = class UserController {
    constructor(userService, authService) {
        this.userService = userService;
        this.authService = authService;
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
    (0, common_1.UseGuards)((0, passport_1.AuthGuard)('jwt')),
    (0, swagger_1.ApiBearerAuth)(),
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
    (0, swagger_1.ApiTags)('Users'),
    (0, common_1.Controller)('/users'),
    __metadata("design:paramtypes", [user_service_1.UserService,
        auth_service_1.AuthService])
], UserController);
//# sourceMappingURL=user.controller.js.map