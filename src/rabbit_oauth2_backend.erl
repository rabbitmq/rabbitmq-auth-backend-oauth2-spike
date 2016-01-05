-module(rabbit_oauth2_backend).

-behavior(oauth2_backend).

-include_lib("rabbit_common/include/rabbit.hrl").

%%% Behavior API
-export([authenticate_user/2]).
-export([authenticate_client/2]).
-export([get_client_identity/2]).
-export([associate_access_code/3]).
-export([associate_refresh_token/3]).
-export([associate_access_token/3]).
-export([resolve_access_code/2]).
-export([resolve_refresh_token/2]).
-export([resolve_access_token/2]).
-export([revoke_access_code/2]).
-export([revoke_access_token/2]).
-export([revoke_refresh_token/2]).
-export([get_redirection_uri/2]).
-export([verify_redirection_uri/3]).
-export([verify_client_scope/3]).
-export([verify_resowner_scope/3]).
-export([verify_scope/3]).

-export([setup_schema/0]).
-export([vhost_access/2, resource_access/3]).

-rabbit_boot_step({rabbit_auth_backend_oauth_mnesia,
                   [{description, "authosation oauth2: mnesia"},
                    {mfa, {?MODULE, setup_schema, []}},
                    {requires, database},
                    {enables, external_infrastructure}]}).

-rabbit_boot_step({rabbit_auth_backend_oauth_backend_env,
                   [{description, "authosation oauth2: oauth2 backend"},
                    {mfa, {?MODULE, oauth2_backend_env, []}},
                    {requires, pre_boot},
                    {enables, kernel_ready}]}).

-define(TOKEN_TABLE, rabbit_oauth_token).
-define(ETS_TABLE_CODE, rabbit_oauth_code).
-define(ETS_TABLE_REFRESH, rabbit_oauth_refresh).
-define(BACKEND, rabbit_auth_backend_internal).

-record(token, {
    token, 
    context
    }).

-compile(export_all).

oauth2_backend_env() ->
    application:set_env(oauth2, backend, rabbit_oauth2_backend).

%% Behaviour functions --------------------------------------------------------

authenticate_user({Username, Password}, Ctx) ->
    rabbit_log:info("User ~p Pass ~p", [Username, Password]),
    case ?BACKEND:user_login_authentication(Username, [{password, Password}]) of
        {refused, _Err} -> {error, notfound};
        {refused, Format, Arg} -> {error, notfound};
        {ok, AuthUser} -> {ok, {Ctx, AuthUser}}
    end.

associate_access_token(AccessToken, Context, AppContext) ->
    ok = save(AccessToken, Context),
    {ok, AppContext}.

resolve_access_token(AccessToken, AppContext) ->
    case lookup(AccessToken) of
        {ok, Context} -> {ok, {AppContext, Context}};
        {error, notfound} -> {error, notfound}
    end.

revoke_access_token(AccessToken, AppContext) ->
    rabbit_misc:execute_mnesia_transaction(
        fun() ->
            ok = mnesia:delete({?TOKEN_TABLE, AccessToken})
        end),
    {ok, AppContext}.

associate_access_code(AccessCode, Context, AppContext) ->
    ets:insert(?ETS_TABLE_CODE, {AccessCode, Context}),
    {ok, AppContext}.

associate_refresh_token(RefreshToken, Context, AppContext) ->
    ets:insert(?ETS_TABLE_REFRESH, {RefreshToken, Context}),
    {ok, AppContext}.

resolve_access_code(AccessCode, AppContext) ->
    case ets:lookup(?ETS_TABLE_CODE, AccessCode) of
        []             -> {error, notfound};
        [{_, Context}] -> {ok, {AppContext, Context}}
    end.

resolve_refresh_token(RefreshToken, AppContext) ->
    case ets:lookup(?ETS_TABLE_REFRESH, RefreshToken) of
        []             -> {error, notfound};
        [{_, Context}] -> {ok, {AppContext, Context}}
    end.

revoke_access_code(AccessCode, AppContext) ->
    ets:delete(?ETS_TABLE_CODE, AccessCode),
    {ok, AppContext}.

revoke_refresh_token(RefreshToken, AppContext) ->
    ets:delete(?ETS_TABLE_REFRESH, RefreshToken),
    {ok, AppContext}.

verify_scope(Scope, Scope, AppContext) -> {ok, {AppContext, Scope}};
verify_scope(_, _, _)                  -> {error, invalid_scope}.

verify_resowner_scope(AuthUser, Scope, Ctx) -> 
    ScopePermissions = parse_scope(Scope),
    ValidScope = lists:filtermap(
        fun({Resource, Permission, ScopeEl}) ->
            case ?BACKEND:check_resource_access(AuthUser, 
                                                Resource, 
                                                Permission) of
                false -> false;
                true -> {true, ScopeEl}
            end
        end, 
        ScopePermissions),
    ScopePolicy = application:get_env(rabbitmq_auth_backend_oauth, 
                                      scope_policy, 
                                      matching),
    case {ValidScope, ScopePolicy} of
        {[], _}       -> {error, invalid_scope};
        {Scope, _}    -> {ok, {Ctx, Scope}};
        {_, matching} -> {ok, {Ctx, Scope}};
        _             -> {error, invalid_scope}
    end.

authenticate_client(_, _) -> {error, notfound}.
get_client_identity(_, _) -> {error, notfound}.

get_redirection_uri(_, _)       -> {error, notfound}.
verify_redirection_uri(_, _, _) -> {error, mismatch}.
verify_client_scope(_, _, _)    -> {error, invalid_scope}.

%% API functions --------------------------------------------------------------

vhost_access(VHost, Ctx) ->
    lists:any(
        fun({#resource{ virtual_host = VH }, _}) ->
            VH == VHost
        end,
        get_scope_permissions(Ctx)).

resource_access(Resource, Permission, Ctx) ->
    lists:any(
        fun({Res, Perm}) ->
            Res == Resource andalso Perm == Permission
        end,
        get_scope_permissions(Ctx)).
%% DB functions ---------------------------------------------------------------

save(AccessToken, Context) ->
    TokenRecord = #token{token = AccessToken, context = Context},
    rabbit_misc:execute_mnesia_transaction(
        fun () ->
            ok = mnesia:write(?TOKEN_TABLE, TokenRecord, write)
        end).

lookup(AccessToken) ->
    case rabbit_misc:dirty_read({?TOKEN_TABLE, AccessToken}) of
        {error, not_found} -> {error, notfound};
        {ok, #token{context = Context}} -> {ok, Context}
    end.

setup_schema() ->
    mnesia:create_table(?TOKEN_TABLE,
                             [{attributes, record_info(fields, token)},
                              {record_name, token},
                              {type, set}]),
    mnesia:add_table_copy(?TOKEN_TABLE, node(), ram_copies),
    mnesia:wait_for_tables([?TOKEN_TABLE], 30000),
    ok.

%% Internal -------------------------------------------------------------------

get_scope_permissions(Ctx) -> 
    case lists:keyfind(<<"scope">>, 1, Ctx) of
        {_, Scope} -> 
            [ {Res, Perm} || {Res, Perm, _ScopeEl} <- parse_scope(Scope) ];
        false -> []
    end.

parse_scope(Scope) when is_list(Scope) ->
    lists:filtermap(
        fun(ScopeEl) ->
            case parse_scope_el(ScopeEl) of
                ignore -> false;
                Perm   -> {true, Perm}
            end
        end,
        Scope).

parse_scope_el(ScopeEl) when is_binary(ScopeEl) ->
    case binary:split(ScopeEl, <<"_">>, [global]) of
        [VHost, KindCode, PermCode | Name] ->
            Kind = case KindCode of
                <<"q">>  -> queue;
                <<"ex">> -> exchange;
                <<"t">>  -> topic;
                _        -> ignore
            end,
            Permission = case PermCode of
                <<"conf">>  -> configure;
                <<"write">> -> write;
                <<"read">>  -> read;
                _           -> ignore
            end,
            case Kind == ignore orelse Permission == ignore of
                true -> ignore;
                false ->
                    {
                        #resource{
                            virtual_host = VHost, 
                            kind = Kind, 
                            name = binary_join(Name, <<"_">>)},
                        Permission,
                        ScopeEl
                    }
            end;
        _ -> ignore
    end.

binary_join([B|Bs], Sep) ->
    iolist_to_binary([B|add_separator(Bs, Sep)]);                                                  
binary_join([], _Sep) ->                                       
    <<>>.                                                
                                                         
add_separator([B|Bs], Sep) ->                               
    [Sep, B | add_separator(Bs, Sep)];                        
add_separator([], _) ->                                  
    [].                                                  


