/**
 * The one shape of a registered client id: 2-63 characters of a-z, 0-9, '.',
 * '_' or '-', starting with a letter or digit.
 *
 * Storage, the admin router and the published OpenAPI schema all validate the
 * same ids, so the rule lives here to keep them from drifting apart.
 */
export const CLIENT_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{1,62}$/;
