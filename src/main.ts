// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    transform: true,
    forbidNonWhitelisted: true,
    errorHttpStatusCode: 400,
  }));

  const config = new DocumentBuilder()
    .setTitle(process.env.APP_NAME)
    .setDescription(process.env.APP_DESCRIPTION)
    .setVersion(process.env.APP_VERSION)
    .addBearerAuth()
    // .addTag('tag')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('/swagger', app, document);
  SwaggerModule.setup('/', app, document);

  await app.listen(process.env.PORT);
}
bootstrap();
