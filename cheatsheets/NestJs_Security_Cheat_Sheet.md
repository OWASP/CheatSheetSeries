# NestJS Security Cheat Sheet

## Introduction

NestJS is a progressive Node.js framework built with TypeScript. While it provides powerful abstractions through decorators and dependency injection, these features can introduce security vulnerabilities if misconfigured. This cheat sheet focuses on NestJS-specific security patterns that complement the [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md).

**Key Principle:** NestJS security relies on understanding the request lifecycle and applying controls at the correct layer.

## Request Lifecycle

Security controls must be applied in the correct order:

```
Request → Middleware → Guards → Pipes → Handler → Response
            ↓            ↓         ↓
          CORS       Auth/Authz  Validation
          Helmet
```

**Critical:** Misplacing security logic breaks defense-in-depth. Guards protect *who* accesses resources; Pipes protect *what* data enters your system.

## Mass Assignment Protection

### The Problem

DTOs alone provide no protection. Without proper ValidationPipe configuration, attackers can inject arbitrary fields.

### Solution

**Install Dependencies:**
```bash
npm install class-validator class-transformer
```

**Create DTOs with Validation:**
```typescript
// create-user.dto.ts
import { IsEmail, IsString, MinLength } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(12)
  password: string;

  @IsString()
  name: string;
  // Note: 'role' is NOT defined - any attempt to pass it will be rejected
}
```

**Configure Global ValidationPipe:**
```typescript
// main.ts
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,              // Strip non-whitelisted properties
      forbidNonWhitelisted: true,   // Throw error if extra properties exist
      transform: true,               // Transform to DTO instances
    }),
  );

  await app.listen(3000);
}
```

**CRITICAL:** Using only `whitelist: true` is insufficient. It silently removes properties, allowing attackers to send large payloads that waste validation resources. Always use `forbidNonWhitelisted: true` for active rejection (defense-in-depth).

**Attack Prevention Example:**
```bash
# Attacker payload
POST /users
{ "email": "user@test.com", "password": "pass", "role": "admin" }

# With forbidNonWhitelisted: true
→ 400 Bad Request: "property role should not exist"

# Without forbidNonWhitelisted: true
→ 201 Created (silently strips 'role', wastes resources)
```

## Authentication and Authorization

### JWT Authentication

**Install Dependencies:**
```bash
npm install @nestjs/jwt @nestjs/passport passport passport-jwt
```

**Configure JWT Module:**
```typescript
// auth.module.ts
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET,     // Never hardcode
      signOptions: {
        expiresIn: '15m',                 // Short-lived tokens
        algorithm: 'HS256',
      },
    }),
  ],
})
export class AuthModule {}
```

**Create JWT Guard:**
```typescript
// jwt-auth.guard.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  handleRequest(err: any, user: any) {
    if (err || !user) {
      throw new UnauthorizedException('Invalid token');
    }
    return user;
  }
}
```

### Role-Based Access Control

**Define Roles:**
```typescript
// roles.decorator.ts
import { SetMetadata } from '@nestjs/common';

export enum Role {
  User = 'user',
  Admin = 'admin',
}

export const ROLES_KEY = 'roles';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
```

**Create Roles Guard:**
```typescript
// roles.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<Role[]>(ROLES_KEY, context.getHandler());
    if (!requiredRoles) return true;

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some(role => user.roles?.includes(role));
  }
}
```

**Apply Guards (Order Matters!):**
```typescript
@Controller('admin')
@UseGuards(JwtAuthGuard, RolesGuard)  // Auth BEFORE Roles!
export class AdminController {
  @Roles(Role.Admin)
  @Get('data')
  getAdminData() {
    return { data: 'sensitive' };
  }
}
```

**CRITICAL:** Always apply `JwtAuthGuard` before `RolesGuard`. Reversing the order allows unauthenticated users to probe role requirements.

## Security Headers with Helmet

**Install Helmet:**
```bash
npm install helmet
```

**Configure in main.ts:**
```typescript
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
    },
  }));

  await app.listen(3000);
}
```

**Apply Helmet FIRST:** Place before `app.enableCors()` and other middleware to ensure headers are set on all responses.

## CORS Configuration

**Secure CORS Setup:**
```typescript
// main.ts
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: process.env.ALLOWED_ORIGINS?.split(','),
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 3600,
  });

  await app.listen(3000);
}
```

**Environment Variable:**
```env
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```

**Common Mistake:**
```typescript
// NEVER do this!
app.enableCors({
  origin: '*',           // Dangerous!
  credentials: true,     // Invalid combination
});
```

When `credentials: true`, origin cannot be wildcard. Browsers will block this configuration.

## Rate Limiting

**Install Throttler:**
```bash
npm install @nestjs/throttler
```

**Global Configuration:**
```typescript
// app.module.ts
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    ThrottlerModule.forRoot([{
      ttl: 60000,     // 60 seconds
      limit: 100,     // 100 requests per window
    }]),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
```

**Custom Limits for Auth Endpoints:**
```typescript
import { Throttle } from '@nestjs/throttler';

@Controller('auth')
export class AuthController {
  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 attempts/min
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }
}
```

## SQL Injection Prevention

**Safe: Use Repository Pattern**
```typescript
// users.service.ts
async findByEmail(email: string): Promise<User> {
  return this.usersRepository.findOne({ where: { email } });
}
```

**Safe: Query Builder with Parameters**
```typescript
async findActiveUsers(minAge: number): Promise<User[]> {
  return this.usersRepository
    .createQueryBuilder('user')
    .where('user.age >= :minAge', { minAge })
    .getMany();
}
```

**Vulnerable: String Concatenation**
```typescript
// NEVER DO THIS!
async unsafeQuery(email: string) {
  return this.usersRepository.query(
    `SELECT * FROM users WHERE email = '${email}'`  // SQL Injection!
  );
}
```

**Attack Example:**
```typescript
email = "admin' OR '1'='1"
// Result: SELECT * FROM users WHERE email = 'admin' OR '1'='1'
// Returns ALL users!
```

## File Upload Security

**Secure Upload Configuration:**
```typescript
import { diskStorage } from 'multer';
import { extname } from 'path';

export const imageUploadOptions = {
  storage: diskStorage({
    destination: './uploads',
    filename: (req, file, cb) => {
      const uniqueName = `${Date.now()}${extname(file.originalname)}`;
      cb(null, uniqueName);
    },
  }),
  fileFilter: (req, file, cb) => {
    const allowedMimes = ['image/jpeg', 'image/png'];
    if (!allowedMimes.includes(file.mimetype)) {
      return cb(new Error('Invalid file type'), false);
    }
    cb(null, true);
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
  },
};
```

**Apply to Controller:**
```typescript
import { FileInterceptor } from '@nestjs/platform-express';

@Post('upload')
@UseInterceptors(FileInterceptor('file', imageUploadOptions))
uploadFile(@UploadedFile() file: Express.Multer.File) {
  return { filename: file.filename };
}
```

## Environment Variables

**Install Config Module:**
```bash
npm install @nestjs/config joi
```

**Configure with Validation:**
```typescript
// app.module.ts
import { ConfigModule } from '@nestjs/config';
import * as Joi from 'joi';

@Module({
  imports: [
    ConfigModule.forRoot({
      validationSchema: Joi.object({
        NODE_ENV: Joi.string().valid('development', 'production').required(),
        JWT_SECRET: Joi.string().min(32).required(),
        DATABASE_URL: Joi.string().required(),
      }),
    }),
  ],
})
export class AppModule {}
```

**Never hardcode secrets:**
```typescript
const secret = 'my-secret-key';

const secret = process.env.JWT_SECRET;
```

## Error Handling

**Global Exception Filter:**
```typescript
import { ExceptionFilter, Catch, HttpException, HttpStatus } from '@nestjs/common';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    
    const status = exception instanceof HttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const message = process.env.NODE_ENV === 'production'
      ? 'An error occurred'
      : exception instanceof HttpException
        ? exception.message
        : 'Internal server error';

    response.status(status).json({
      statusCode: status,
      message,
      timestamp: new Date().toISOString(),
    });
  }
}
```

**Apply in main.ts:**
```typescript
app.useGlobalFilters(new GlobalExceptionFilter());
```

**Never expose stack traces in production.**

## Security Checklist

### Before Production:
- [ ] ValidationPipe configured with `whitelist: true` AND `forbidNonWhitelisted: true`
- [ ] All DTOs use `class-validator` decorators
- [ ] JWT secret in environment variables (min 32 chars)
- [ ] Guards applied in correct order (Auth → Roles)
- [ ] Helmet configured and applied first
- [ ] CORS allows only specific origins
- [ ] Rate limiting enabled globally
- [ ] File uploads validate type and size
- [ ] All database queries use parameterization
- [ ] Error messages sanitized for production
- [ ] HTTPS enforced
- [ ] Dependencies scanned with `npm audit`

## Quick Reference

| Security Control | Where to Apply | Key Setting |
|-----------------|----------------|-------------|
| Input Validation | Global Pipe | `forbidNonWhitelisted: true` |
| Authentication | Guard | Apply before RolesGuard |
| CORS | Middleware | Specific origins only |
| Rate Limiting | Global Guard | Stricter on auth routes |
| Security Headers | Middleware | Apply Helmet first |
| SQL Injection | Repository/Query Builder | Always parameterize |
| File Upload | Interceptor | Validate MIME + size |

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Cheat Sheet](Nodejs_Security_Cheat_Sheet.md)
- [NestJS Security Documentation](https://docs.nestjs.com/security/helmet)
- [TypeORM Security](https://typeorm.io/)

## Conclusion

NestJS security requires understanding the framework's lifecycle and applying controls at the correct layer. The key is configuring ValidationPipe, Guards, and middleware in the right order with the right settings. Always use defense-in-depth: multiple layers of security controls working together.
