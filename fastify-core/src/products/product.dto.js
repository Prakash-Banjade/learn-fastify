export const productCreateDto = {
    type: 'object',
    properties: {
        name: { type: 'string' },
        category: { type: 'string' }
    },
    required: ['name', 'category']
}

export const productUpdateDto = {
    type: 'object',
    properties: {
        name: { type: 'string' },
        category: { type: 'string' }
    }
}

export const productResponseDto = {
    type: 'object',
    properties: {
        id: { type: 'number' },
        name: { type: 'string' },
        category: { type: 'string' }
    },
    required: ['id', 'name']
}

export const productListResponseDto = {
    200: {
        type: 'array',
        items: productResponseDto
    }
}

export const productMutationSchema = {
    200: {
        type: 'object',
        properties: {
            message: { type: 'string' }
        },
        required: ['message']
    }
}