import { AuthService } from './auth.service';
export declare class AuthController {
    private authService;
    constructor(authService: AuthService);
    login(body: any): Promise<{
        access_token: string;
    }>;
    prueba(): Promise<{
        esto: string;
    }>;
}
