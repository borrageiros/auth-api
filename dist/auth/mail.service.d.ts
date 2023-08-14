export declare class MailService {
    private transporter;
    constructor();
    sendMail(to: string, subject: string, text: string): Promise<void>;
}
