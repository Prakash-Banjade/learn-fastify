export const currentUserResponseSchema = {
    type: 'object',
    properties: {
        id: { type: 'number' },
    },
    required: ['id']
}