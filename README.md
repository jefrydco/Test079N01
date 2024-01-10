# jitera_nestjs_app

## Table of Contents

- [Requirements](#requirements)
- [Initialization](#initialization)
- [Setup](#setup)
- [Database](#database)
- [Api Document](#api-documents)
- [Authentication](#authentication)
- [Sending Email](#sending-email)
- [File System](#file-system)
- [Credentials](#credentials)
- [Deployment](#deployment)
- [Supplement](#supplement)

## Requirements

- Docker 19.x
  If you run the project locally, the followings are required.
- Node 16.x
- Yarn 1.22.x
- Postgres 8.0.x

## Setup

Setup procedure of development environment.
Run `cp .env.example .env`

### Docker environment

Build docker containers

```bash
docker-compose build
```

Create new database. Note: skip this step if database existed

```bash
docker-compose run api yarn db:create
```

Generate new migrations. Note: skip this step if migrations existed in `src/database/migrations`

```bash
docker-compose run api yarn db:generate
```

Apply migrations

```bash
docker-compose run api yarn db:run
```

Start the app

```bash
docker-compose up
```

### Local environment

Install dependencies

```bash
yarn install
```

Start postgres and redis services

```bash
docker-compose up -d db redis
```

Update .env file

```bash
DATABASE_HOST=localhost
REDIS_HOST=localhost
MAILDEV_HOST=localhost
```

Create new database. Note: skip this step if database existed

```bash
yarn db:create
```

Generate new migrations. Note: skip this step if migrations existed in `src/database/migrations`

```bash
yarn db:generate
```

Apply migrations

```bash
yarn db:run
```

Start the app

```bash
yarn start
```

## Database

Some useful commands for database:

- Create new database

```
yarn db:create
```

- Drop database schema

```
yarn db:drop
```

- Generate migration from entity schema

```
yarn db:generate
```

- Apply migrations

```
yarn db:run
```

- Revert migrations

```
yarn db:rollback
```

Our command built on TypeOrm cli. In case you want run other TypeOrm command, you can use that command with the prefix
`yarn typeorm`

Example: To show all migrations

```
yarn typeorm migration:show
```

[TypeOrm CLI](https://orkhan.gitbook.io/typeorm/docs/using-cli)

## API Documents

Use the link below to access api document:

```url
http://localhost:3000/api-docs
```

Input the credentials:

```
Username: swagger
Password: swagger
```

You can adjust swagger url and credentials by edit these configs in .env file

```
SWAGGER_PATH=api-docs
SWAGGER_USERNAME=swagger
SWAGGER_PASSWORD=swagger
```

## Repository

##### How to add repository to service:

Import `repository` into module

```typescript
import { Applicant } from '@entities/applicants';
import { ApplicantRepository } from './applicants.repository';
import { provideCustomRepository } from 'src/utils/repository';

@Module({
  imports: [NestjsFormDataModule],
  providers: [provideCustomRepository(Applicant, ApplicantRepository), ApplicantService], // <-- Add custom repository here
  controllers: [ApplicantController],
})

```

Using `repository` mothod inside you service action

```typescript
@Injectable()
export class ApplicantService {
  constructor(
    @InjectRepository(Applicant) // <-- Add decorator
    private readonly repository: ApplicantRepository // <-- And this declare
  ) {}

this.repository.findMany({ .... })
```

##### How to query with repository:

```typescript

const conditions = [
  {
    column: 'full_name',
    value: 'hello',
    operator: QueryOperators.START_WITH,
    whereType: QueryWhereType.WHERE,
  },
  {
    whereType: QueryWhereType.WHERE_AND,
    conditions: [
      {
        column: 'phone_number',
        value: '0002,
        operator: QueryOperators.START_WITH,
        whereType: QueryWhereType.WHERE_OR,
      },
      {
        column: 'phone_number',
        value: '0001',
        operator: QueryOperators.START_WITH,
        whereType: QueryWhereType.WHERE_OR,
      },
    ]
  },
  {
    whereType: QueryWhereType.WHERE_AND,
    builder: (qb) => {
      qb.where('birthday', '=', '1')
    }
  },
]

const relations: QueryRelation[] = [
  { column: 'applicant_languages', alias: 'applicant_languages' },
  { column: 'job_experiences', alias: 'job_experiences' },
];

this.repository.findMany({ conditions, relations })

// -> SELECT * FROM ... WHERE full_name = '' AND (phone_number = '' OR phone_number = '') AND birthday = '1'
// Included relation data: job_experiences, applicant_languages

```

##### How to use transaction in service:

Inject datasource to servcei
```typescript
@Injectable()
export class ApplicantService {
  constructor(
    private readonly dataSource: DataSource,
    @InjectRepository(Applicant)
    private readonly repository: ApplicantRepository,
  ) {}
```

Create query runner to perform transaction

```typescript
const queryRunner = this.dataSource.createQueryRunner();

await queryRunner.connect();
await queryRunner.startTransaction();
try {
  const data = {
    email: 'email21@gmail.com',
    income_range_id: 1,
    management_experience_id: 1
  };
  await this.repository.createOne({
    data
  }, queryRunner)

  await this.anotherRepository.updateOne({
    data: {
      full_name: 'test'
    },
    conditions: [
      {
        column: 'applicants.email',
        value: 'email21@gmail.com',
        operator: QueryOperators.EQUAL,
        whereType: QueryWhereType.WHERE_AND,
      }
    ]
  }, queryRunner)

  await queryRunner.commitTransaction();
} catch (err) {
  // since we have errors lets rollback the changes we made
  await queryRunner.rollbackTransaction();
} finally {
  // you need to release a queryRunner which was manually instantiated
  await queryRunner.release();
}
```


## Authentication

#### Confirmation:

Sends email with confirmation instructions and verifies whether an account is already confirmed during sign in. Following these steps to enable confirmation feature:

- Add these configs into .env file

```
AUTH_SEND_CONFIRMATION_EMAIL=true
AUTH_CONFIRMATION_URL=[confirmation link attach in email]
```

- Follow [Sending Email](###sending-email) section to setup mail service

#### Reset Password

Change password by using registration email. After requesting reset password, an email will be sent with a token attached in a link. Using this token for change new password. Following these steps to enable reset password feature:

- Add these configs into .env file

```
AUTH_RESET_PASSWORD_URL=[reset password link attach in email]
AUTH_RESET_PASSWORD_IN=[hour] // default is 1 hour
```

- Follow [Sending Email](###sending-email) section to setup mail service

## Sending Email

Currently, we're only supporting 3 email providers: SES and SendGrid and Maildev(For Development)

- Use these configs in .env file in order to config email setting

```
MAIL_PROVIDER=[ses | sendgrid | maildev] // Default is 'maildev'
MAIL_FROM=[email sender]
// For MAILDEV
MAILDEV_HOST=maildev // Change to `localhost` in case you run project in local instead of docker
// For using SES
SES_USERNAME=[SES Username]
SES_PASSWORD=[SES Password]
// For SENDGRID
SENDGRID_API_KEY=[SendGrid Api Key]
```

##### Preview Email

In development, we're using [maildev](https://github.com/maildev/maildev) as a local smtp mail server. You can access the url `http://localhost:1080/` with the credentials below to view sent emails

```
username: admin
password: admin
```

##### How to use email service:

Import `EmailService` in `MailModule` into your service

```typescript
import { MailService } from 'src/shared/mail/mail.service';

@Injectable()
export class YouService {
  constructor(private readonly mailService: MailService) {}
}
```

Call `sendMail` action inside you service action with these options

```typescript
await this.mailService.sendMail({
  to: 'email-receiver',
  subject: 'email-subject',
  template: 'template-name-without-extension',
  context: {
    // The payload using for template
    data: 'data',
  },
});
```

Compose a email template file with exact file name you using above in folder:

```
shared/mail/templates/[template-name].hbs
```

Handlebars syntax:

```
https://handlebarsjs.com/
```

## File System

##### 1. File Management

We're using library [nestjs-storage](https://github.com/codebrewlab/nestjs-storage) to manage files. Please read library document to know how to using

We have 2 default disks: `local` and `s3`. The default disk is `local`. To change default disk we have 2 ways:

Go to config/index.ts and adjust this line

```typescript
storage: {
    default: process.env.STORAGE_DISK || 'local', // => change the default disk here
  },
```

OR

Add this config in .env file

```
STORAGE_DISK=[select disk name]
```

##### 2. File Upload

We're using this the library [nestjs-form-data](https://github.com/dmitriy-nz/nestjs-form-data) for managing file upload. Follow the steps below to setup file upload for a module

Define file attachment in entity database:

```typescript
import { StorageFile } from '@entities/storage_files'
import { OneToOne, JoinColumn,  ManyToMany, JoinTable } from 'typeorm';

export FeatureEntity {
  // ... other fields

  // Single File
  @OneToOne(() => StorageFile, { onDelete: 'CASCADE' })
  @JoinColumn()
  file: StorageFile


  // Multiple Files
  @ManyToMany(() => StorageFile, { onDelete: 'CASCADE' })
  @JoinTable()
  files: StorageFile[]
}
```

Add NestjsFormDataModule in module file:

```typescript
// feature.module.ts
import { NestjsFormDataModule } from 'nestjs-form-data';

@Module({
  imports: [
    TypeOrmModule.forFeature([Product]),
    NestjsFormDataModule, // => Add NestjsFormDataModule here
  ],
  providers: [FeatureService],
  controllers: [FeatureController],
})
export class FeatureModule {}
```

Add ApiUpload decorator in controller action

```typescript
// feature.controller.ts
import { ApiUpload } from '@decorators/api-upload.decorator.ts';

export class FeatureController {
  @Post('/api/upload')
  @ApiUpload() // => Add ApiUpload here
  create(@Body() request: UploadDTO): Promise<UploadResponseDTO> {
    return this.featureService.addFile(request);
  }
}
```

Add file validation in DTO

```typescript
import { FileSystemStoredFile } from 'nestjs-form-data';
import { FileField } from 'src/decorators/field.decorator';

export class UploadDTO {
  //...other properties

  // Single File
  @FileField({ fileSize: 1, fileType: 'image' })
  file: FileSystemStoredFile;

  // Multiple Files
  @FileField({ each: true, fileSize: 1, fileType: 'image' })
  files: FileSystemStoredFile[];
}
```

Use upload service to store upload file

```typescript
// feature.service.ts
import { UploadService } from 'src/shared/storage/upload.service';

@Injectable()
export class FeatureService extends BaseService<Feature> {
  constructor(
    @InjectRepository(Feature) readonly productRepository: Repository<Feature>,
    private readonly uploadService: UploadService, // Inject upload Service
  ) {
    super(productRepository);
  }

  addFile(dto: UploadDTO) {
    // Single File
    const file = await this.uploadService.uploadFile(dto.file);

    // Multiple Files
    const files = await this.uploadService.uploadFiles(dto.files);
  }
}
```

## Credentials

After exporting project, you will see the folder `src/credentials`. This folder contain secret information that is encrypted for each environment.

#### Usage

- Add this variable to `.env` or environment variable to select environment credentials

```
APP_ENV=[development | staging | production]
```

- Find `master.key` look like below that exporting belong with project and get the environment key

```
development: 8b76dabe74908c0b8f1b8762
staging: 786f57705b073723edd4d42e
production: 746486c9caa1c7f5c1964499
```

- Add that key to `.env` or environment variable to decrypt the information

```
NODE_MASTER_KEY=[environment key]
```

#### Edit Credentials

Use this command to edit the credentials

```
yarn credentials:edit -e [environment] - k [environment key]
```

Example

```
yarn credentials:edit -e production -k 746486c9caa1c7f5c1964499
```

## Deployment

Once you created the staging and production environments in Jitera's DevOps menu, you can deploy to staging by pushing a new commit to `develop` branch, and to production by pushing a new commit to `master` branch.

## REPL

REPL is a simple interactive environment that takes single user inputs, executes them, and returns the result to the user. The REPL feature lets you inspect your dependency graph and call methods on your providers (and controllers) directly from your terminal.

```
yarn run start:repl
```

Example

```
> get(AppService).getHello()

// 'Hello World!'
```


## Supplement

This project was generated by jitera automation, run by Jitera.
