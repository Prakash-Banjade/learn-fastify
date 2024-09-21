import { currentUserResponseSchema } from "./users-schema.js";

const sampleUsers = [
    {
        id: 1,
        name: 'Prakash'
    },
    {
        id: 2,
        name: 'Banjade'
    }
]

// this is equivalent to express router
const userController = (fastify, opts, done) => {
    // you need to define the decorator like this to add the user to the request object because
    // not doing so will change the shape of objects during their lifecycle. REF: https://fastify.dev/docs/latest/Reference/Decorators
    fastify.decorateRequest('user', null);

    fastify.addHook('onRequest', (request, reply, done) => {
        request.user = sampleUsers[0];

        done()
    })

    // defint get All route
    fastify.get('/', (req, reply) => {
        return sampleUsers;
    })

    // now you access the user from the request object
    fastify.get(
        '/me',
        {
            schema:
            {
                response: { 200: currentUserResponseSchema }
            }
        },
        (req, reply) => {
            return {
                id: req.user.id,
            };
        })

    // define dynamic route
    fastify.get('/:id', (req, reply) => {
        return sampleUsers.find((user) => user.id == req.params.id)
    })

    done();
}

export default userController;