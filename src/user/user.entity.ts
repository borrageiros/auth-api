// src/user/user.entity.ts
import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn,
} from 'typeorm';
import { Exclude } from 'class-transformer';

export enum UserRole {
    USER = "user",
    ADMIN = "admin",
    ROOT = "root" // super_admin
} // Defines the possible roles a user can have (enum = enumerated)

@Entity('users')

////////////////// IMPORTANT ///////////////////
// 
// All the private Columns will be configured in PublicUserInfo
//
export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ unique: true, length: 50 })
    username: string;

    @Column({ length: 200 })
    password: string;

    @Column({ unique: true, length: 100 })
    email: string;

    @Column({
        type: "enum",
        enum: UserRole,
        default: UserRole.USER
    })
    role: UserRole;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;

    @Column({default: false})
    actived: boolean;
}

export class PublicUserInfo extends User {
    @Exclude()
    password: string;

    @Exclude()
    email: string;

    @Exclude()
    updatedAt: Date;

    @Exclude()
    actived: boolean;
}
