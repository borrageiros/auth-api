// src/user/user.service.ts
import { Injectable, ConflictException, BadRequestException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Like, Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User, UserRole } from './user.entity';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
    ) { }

    async findAllUsers(): Promise<User[]> {
        return this.userRepository.find();
    }    

    async findOneById(id: number): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id } });
        if (!user) {
            throw new NotFoundException([`No user found with ID ${id}`]);
        }
        return user;
    }

    async findOneByUsername(username: string): Promise<User> {
        const user = await this.userRepository.findOne({ where: { username } });
        if (!user) {
          throw new NotFoundException([`No user found with username ${username}`]);
        }
        return user;
    }

    async findUsersByUsername(username: string): Promise<any> {
        const users = await this.userRepository.find({ 
            where: { 
                username: Like(`%${username}%`) 
            } 
        });
        if (users.length === 0) {
            throw new NotFoundException([`No users found with username containing "${username}"`]);
        }
        return {users: users.map(user => user.username) };
    }

    async findOneByEmail(email: string): Promise<User> {
        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) {
          throw new NotFoundException([`No user found with email ${email}`]);
        }
        return user;
    }

    async findUsersByEmail(email: string): Promise<any> {
        const users = await this.userRepository.find({ 
            where: { 
                email: Like(`%${email}%`) 
            } 
        });
        if (users.length === 0) {
            throw new NotFoundException([`No users found with email containing "${email}"`]);
        }
        return {users: users.map(user => user.username) };
    }

    async changeUsernameConnectedUser(connectedUserId: number, newUsername: string): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id: connectedUserId } });
        user.username = newUsername;
        await this.userRepository.save(user);
        return user;
    }

    async changeEmailConnectedUser(connectedUserId: number, newEmail: string): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id: connectedUserId } });
        user.email = newEmail;
        await this.userRepository.save(user);
        return user;
    }

    async changeUserRole(userId: number, newRole: UserRole): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id: userId } });
        user.role = newRole;
        await this.userRepository.save(user);
        return user;
    }

    // SIGN UP
    async create(createUserDto: CreateUserDto): Promise<any> {
        const user = new User();
        user.username = createUserDto.username;
        user.email = createUserDto.email;

        const salt = await bcrypt.genSalt();
        user.password = await bcrypt.hash(createUserDto.password, salt);

        try {
            await this.userRepository.save(user);
            const { password, ...result } = createUserDto;  // Excluyendo password del DTO
            return result;
        } catch (error) {
            // EL RESTO DE ERRORES SE MANEJAN DESDE EL DTO "./dto/create-user.dto"
            if (error.code === 'ER_DUP_ENTRY') {
                if (error.sqlMessage.includes(user.username)) {
                    throw new ConflictException(['Username already in use']);
                } else if (error.sqlMessage.includes(user.email)) {
                    throw new ConflictException(['Email already in use']);
                } else {
                    throw new ConflictException(['Duplicate entry']);
                }
            } else {
                throw new BadRequestException(['Undefined error']);
            }
        }
    }
}
