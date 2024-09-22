export const loginSchema = {
    schema: {
        body: {
            type: 'object',
            properties: {
                email: { type: 'string' },
                password: { type: 'string' }
            },
            required: ['email', 'password']
        },
        response: {
            200: {
                type: 'object',
                properties: {
                    token: { type: 'string' }
                },
                required: ['token']
            },
            400: {
                type: 'object',
                properties: {
                    message: { type: 'string' }
                },
                required: ['message']
            }
        }
    }
}