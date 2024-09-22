import { loginSchema } from "./auth-schema.js"
import { AuthService } from "./auth.service.js"

export const authController = (fastify, opts, done) => {
    const authService = new AuthService(fastify);
    
    fastify.post('/login', loginSchema, authService.login)

    done();
}