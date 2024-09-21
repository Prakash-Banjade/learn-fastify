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

    // defint get All route
    fastify.get('/', (req, reply) => {
        return sampleUsers;
    })

    // define dynamic route
    fastify.get('/:id', (req, reply) => {
        return sampleUsers.find((user) => user.id == req.params.id)
    })

    done();
}

export default userController;