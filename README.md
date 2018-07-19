# RabbitMQ OAuth 2.0 Authorization Backend.

This plugin aims to provide OAuth 2.0 authorization for RabbitMQ clients.

## Project Maturity

This project ws **a spike that's no longer under development**. See [rabbitmq-auth-backend-oauth2](https://github.com/rabbitmq/rabbitmq-auth-backend-oauth2) for an OAuth 2/JWT [authentication and authorisation backend](http://www.rabbitmq.com/access-control.html) for RabbitMQ.

## Auth workflow

### Token grant.

Internal:

Client use some grant to request `access_token` in some `scope`.

Token is being created with scope and expire after some time. 
Client can also be issued `refresh_token` to refresh `access_token`.

If client use user credentioals, user access permissions to `scope` is being checked.

External:

External auth server sends request to token handler to create `access_token` with scope and expiry.

### Client access.

Client connects to RabbitMQ using `access_token` as username and will have access to resources based on `scope`


## Components

This module contin following parts:

1. Rabbit auth backend `rabbit_auth_backend_oauth.erl`. Module to authorize clients with `access_token` used as username.
2. Oauth backend (yeah, also backend) `rabbit_oauth2_backend.erl`. Module to work with OAuth2 clients and tokens, direct them to mnesia storage, manage scopes. (https://github.com/kivra/oauth2/blob/master/src/oauth2_backend.erl)
3. OAuth2 http server `rabbit_oauth2_auth.erl`. Cowboy handler to grant access codes and tokens. Has no references to rabbitmq and works with oauth library only. Can be made separate plugin.
4. Token endpoint for external Auth server `rabbit_oauth2_access_token.erl`. Accepts requests like `{"acess_token":..., "scope":..., "expires_in":..., "created_at":...}` and creates `access_token` record in DB. Can be used by external authorization server to issue tokens for rabbitmq.

Endpoint is configured by application env `auth_server`, which can be `{internal, Conf}` or `{external, Conf}`. To set up internal (`rabbit_oauth2_auth`) or external (`rabbit_oauth2_access_token`) auth server.

Grant and client types are managed by authorization server handler only.

## Scopes

*Scopes is discussion topic, because current implementation provide not enough flexibility.*

To define `access_token` access to specific VHost or resource OAuth2 scopes are used.
Scope can be a set of strings. Each element in scope define access to specific resource permission.

Format of scope element: `<vhost>_<kind>_<permission>_<name>`, where 

- `<vhost>` - vhost of recource
- `<kind>` can be `q` - queue, `ex` - exchange, or `t` - topic
- `<permission>` - access permission (configure, read, write)
- `<name>` - resource name (exact, no regexps allowed)

When granting `access_code` to scope on behalf of some user scope is checked to be available to this user. For this purpose another `auth_backend` is used. `rabbit_oauth2_backend.erl` currently contains constant `rabbit_auth_backend_internal`, can be configurable.

As you can see, scope syntax restrict some vhosts and it is not easy to support regex resource names, because granting regex scope to regex user permissions will require solving regex inclusion problem (which is not so easy)

