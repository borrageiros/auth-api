// import { ScheduleModule } from '@nestjs/schedule';

// @Module({
//   imports: [
//     ScheduleModule.forRoot(),
//     //... otros módulos
//   ],
//   controllers: [/* ... */],
//   providers: [/* ... */],
// })
// export class AppModule {}







// import { Injectable, Logger } from '@nestjs/common';
// import { Cron } from '@nestjs/schedule';
// import { UserService } from './user.service';

// @Injectable()
// export class TasksService {
//   private readonly logger = new Logger(TasksService.name);

//   constructor(private userService: UserService) {}

//   @Cron('59 23 * * *')  // Esto se ejecuta todos los días a las 23:59 (un minuto antes de medianoche)
//   async handleInactiveUsers() {
//     this.logger.debug('Started checking for inactive users');
    
//     const currentDate = new Date();
//     const thresholdDate = new Date(currentDate);
//     thresholdDate.setHours(0, 0, 0, 0);  // Establecer el inicio del día actual

//     const inactiveUsers = await this.userService.findInactiveBeforeDate(thresholdDate);
    
//     for (const user of inactiveUsers) {
//         await this.userService.deleteUser(user.id);
//     }
    
//     this.logger.debug(`Deleted ${inactiveUsers.length} inactive users`);
//   }
// }

