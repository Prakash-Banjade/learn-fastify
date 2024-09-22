const sampleDBUsers = [
    {
        id: 1,
        name: 'Prakash',
        email: "prakash@gmail.com",
        password: '123456',
    },
    {
        id: 2,
        name: 'Banjade',
        email: "banjade@gmail.com",
        password: '123456',
    }
]

export class AuthService {

    constructor(fastify) {
        this.fastify = fastify;
    }

    fastify;

    login = (req, reply) => {
        const { email, password } = req.body;

        const foundAccount = sampleDBUsers.find(user => user.email === email && user.password === password);
        if (!foundAccount) return reply.status(400).send({ message: 'Invalid credentials' });

        const pwdMatch = password === foundAccount.password;
        if (!pwdMatch) return reply.status(400).send({ message: 'Invalid credentials' });

        const payload = {
            id: foundAccount.id
        };

        const token = this.fastify.jwt.sign(payload, { expiresIn: '5m' })

        return { token };
    }
}