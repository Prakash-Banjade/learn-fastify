export const enum Tokens {
    ACCESS_TOKEN_COOKIE_NAME = 'access_token',
    REFRESH_TOKEN_COOKIE_NAME = 'refresh_token',
}

// checks if a string has only letters, numbers, spaces, apostrophes, dots and dashes
export const NAME_REGEX = /(^[\p{L}\d'\.\s\-]*$)/u;