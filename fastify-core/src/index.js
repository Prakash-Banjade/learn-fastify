import Fastify from 'fastify'

const fastify = Fastify({ // create a new instance of fastify, passing in options
    logger: true,
})
const PORT = 3000

// #region FASTIFY ROUTE HANDLERS ============================================================>

// define a get route
fastify.get('/', (req, reply) => { // `reply` is the convension instead of response
    return { // fastify offers a reply object
        message: 'hello world!'
    }
})

// another method for defining route, using route method shorthand
fastify.route({
    method: 'GET',
    url: '/users',
    handler: (req, reply) => {
        return {
            message: 'hello new user'
        }
    }
})

// define dynamic route
fastify.route({
    method: 'GET',
    url: '/users/:id',
    handler: (req, reply) => {
        return {
            message: `hello user with id ${req.params.id}`
        }
    }
})

// #endregion

// #region FASTIFY SCHEMA VALIDATION ============================================================>
/**
|--------------------------------------------------
| FASTIFY ALLOWS SCHEMA DEFINITION TO VALIDATE THE REQUEST BODY, PARAMS AND QUERY AS WELL AS 
| RESPONSE BODY
|--------------------------------------------------
*/
// Define product route handlers with schema
const getRequestSchemaOptions = {
    schema: {
        querystring: {
            properties: {
                name: { type: 'string' },
            },
            required: ['name']
        }
    }
}

fastify.get('/products', getRequestSchemaOptions, (req, reply) => {
    return [
        {
            id: 1,
            name: 'product 1',
            category: 'category 1'
        }
    ]
})

// or you can use the fastify.route method as follows
fastify.route({
    method: 'GET',
    url: '/v2/products',
    schema: {
        querystring: { // validate query params
            properties: {
                name: { type: 'string' },
            },
            // required: ['name'] // mention required query params here
        },
        response: {
            200: {
                type: 'array',
                items: {
                    type: 'object',
                    properties: {
                        id: { type: 'number' },
                        name: { type: 'string' },
                        category: { type: 'string' }
                    },
                    required: ['id', 'name'] // moved inside the object
                }
            }
        }
    },
    handler: (req, reply) => {
        return [
            {
                id: 1,
                name: 'product 1',
                category: 'category 1'
            }
        ]
    }
})

// #endregion

// listen on port 3000
fastify.listen({ port: PORT }, (err, address) => {
    if (err) {
        fastify.log.error(err) // log the error using fatify's logger
        process.exit(1) // exit the process with an error code (1)
    }
    console.log(`Server listening at ${address}`)
})