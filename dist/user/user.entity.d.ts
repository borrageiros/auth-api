export declare enum UserRole {
    USER = "user",
    ADMIN = "admin",
    ROOT = "root"
}
export declare class User {
    id: number;
    username: string;
    password: string;
    email: string;
    role: UserRole;
    createdAt: Date;
    updatedAt: Date;
}
