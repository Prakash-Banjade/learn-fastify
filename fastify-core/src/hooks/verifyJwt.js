// using this function as preValidation in particular request, you can protect the route
// or, use this as fastify.addHook('preValidation', verifyJWT) in top level to protect all routes 
const exludedRoutes = ['/auth/login'];

export const verifyJWT = async (req, reply) => { 
    const { url } = req;

    if (exludedRoutes.includes(url)) {
        return;
    }
    
    try {
        await req.jwtVerify();
    } catch (err) {
        reply.send(err);
    }
};