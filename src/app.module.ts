import { ConfigModule, ConfigService } from '@nestjs/config';
import { Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { TypeOrmModule } from '@nestjs/typeorm';
import { APP_FILTER } from '@nestjs/core';
import { DataSource } from 'typeorm';
import { join } from 'path';
import {
  AcceptLanguageResolver,
  CookieResolver,
  HeaderResolver,
  I18nModule,
  QueryResolver,
} from 'nestjs-i18n';
import { NODE_ENV } from './constants';
import { TypeOrmConfigService } from './database/typeorm-config.service';
import { ShareModule } from './shared/share.module';
import configs from './configs/index';
import modules from './modules/index';
import { HttpExceptionFilter } from './filters/http_exception.filter';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, load: [configs] }),
    TypeOrmModule.forRootAsync({
      useClass: TypeOrmConfigService,
      dataSourceFactory: async (options) => {
        const dataSource = await new DataSource(options).initialize();
        return dataSource;
      },
    }),
    I18nModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        fallbackLanguage: configService.get('app.fallbackLanguage'),
        loaderOptions: {
          path: join(__dirname, 'i18n'),
          watch: configService.get('app.nodeEnv') === NODE_ENV.DEVELOPMENT,
        },
        viewEngine: 'hbs',
      }),
      resolvers: [
        new QueryResolver(['lang', 'l', 'locale']),
        CookieResolver,
        AcceptLanguageResolver,
        {
          use: HeaderResolver,
          useFactory: (configService: ConfigService) => {
            return [configService.get('app.headerLanguage')];
          },
          inject: [ConfigService],
        },
      ],
      inject: [ConfigService],
    }),
    CacheModule.register({ isGlobal: true }),
    ShareModule,
    ...modules,
  ],
  providers: [
    {
      provide: APP_FILTER,
      useClass: HttpExceptionFilter,
    },
  ],
  controllers: [],
})
export class AppModule {}
