import { productCreateDto, productListResponseDto, productMutationSchema } from "./product.dto.js"

export const productController = (fastify, opts, done) => {
    fastify.get('/', { schema: { response: productListResponseDto } }, (req, reply) => {
        fastify.pg.query('SELECT * FROM product', (err, res) => {
            reply.send(err || res.rows)
        })
    })

    fastify.post('/', { schema: { body: productCreateDto, response: productMutationSchema } }, (req, reply) => {
        fastify.pg.query('INSERT INTO product (name, category) VALUES ($1, $2)', [req.body.name, req.body.category], (err, res) => {
            if (err) return reply.send({ message: err instanceof Error ? err.message : 'Something went wrong' })

            reply.send({ message: 'Product created successfully' })
        })
    })

    done();
}