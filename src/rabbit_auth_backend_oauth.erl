%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License
%% at https://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and
%% limitations under the License.
%%
%% The Original Code is RabbitMQ.
%%
%% The Initial Developer of the Original Code is GoPivotal, Inc.
%% Copyright (c) 2007-2015 Pivotal Software, Inc.  All rights reserved.

%% 
%% This is backend for OAuth 2.0 authorization. 
%% It  Allows to use Rabbitmq with OAuth authorization servers.
%% Authorization token is used as Username.

-module(rabbit_auth_backend_oauth).

-include_lib("rabbit_common/include/rabbit.hrl").

-behaviour(rabbit_authn_backend).
-behaviour(rabbit_authz_backend).

-export([description/0]).
-export([user_login_authentication/2, user_login_authorization/1,
         check_vhost_access/3, check_resource_access/3]).

-rabbit_boot_step({rabbit_auth_backend_oauth_mnesia,
                   [{description, "authosation oauth2: mnesia"},
                    {mfa, {rabbit_oauth2_storage, setup_schema, []}},
                    {requires, database},
                    {enables, external_infrastructure}]}).

-rabbit_boot_step({rabbit_auth_backend_oauth_backend_env,
                   [{description, "authosation oauth2: oauth2 backend"},
                    {mfa, {rabbit_oauth2_backend, oauth2_backend_env, []}},
                    {requires, pre_boot},
                    {enables, kernel_ready}]}).

%%--------------------------------------------------------------------

description() ->
    [{name, <<"OAUTH">>},
     {description, <<"OAUTH authentication / authorisation">>}].

%%--------------------------------------------------------------------

user_login_authentication(Token, _AuthProps) ->
    case oauth2:verify_access_token(Token, []) of
        {ok, _} -> {ok, #auth_user{ username = Token, tags = [], impl = none}};
        {error, access_denied} -> {refused, "token ~p rejected", [Token]}
    end.

user_login_authorization(Username) ->
    case user_login_authentication(Username, []) of
        {ok, #auth_user{impl = Impl, tags = Tags}} -> {ok, Impl, Tags};
        Else                          -> Else
    end.

check_vhost_access(#auth_user{username = Username}, VHost, _Sock) ->
    with_token_context(Username, fun(Ctx) ->
        rabbit_oauth2_scope:vhost_access(VHost, Ctx)
    end).

check_resource_access(#auth_user{username = Username}, Resource, Permission) ->
    with_token_context(Username, fun(Ctx) ->
        rabbit_oauth2_scope:resource_access(Resource, Permission, Ctx)
    end).

with_token_context(Token, Fun) ->
    case oauth2:verify_access_token(Token, []) of
        {ok, {_, TokenCtx}} -> Fun(TokenCtx);
        {error, access_denied} -> false
    end.

