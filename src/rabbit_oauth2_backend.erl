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

-export([vhost_access/2, resource_access/3]).
-export([add_access_token/3, add_access_token/4]).
-export([oauth2_backend_env/0]).

-define(BACKEND, rabbit_auth_backend_internal).

-ifdef(TEST).
-compile(export_all).
-endif.

oauth2_backend_env() ->
    application:set_env(oauth2, backend, rabbit_oauth2_backend).

add_access_token(Token, Scope, ExpiresIn) when is_list(Scope), 
                                               is_integer(ExpiresIn) ->
    add_access_token(Token, Scope, ExpiresIn, time_compat:os_system_time(seconds)).

add_access_token(Token, Scope, ExpiresIn, CreatedAt) 
    when is_list(Scope),
         is_integer(ExpiresIn),
         is_integer(CreatedAt) ->
    {ok, []} = associate_access_token(Token, 
                                      [{<<"scope">>, Scope}, 
                                       {<<"expiry_time">>, 
                                        ExpiresIn + CreatedAt}], 
                                      []),
    ok.

%% Behaviour functions --------------------------------------------------------

authenticate_user({Username, Password}, Ctx) ->
    rabbit_log:info("User ~p Pass ~p", [Username, Password]),
    case ?BACKEND:user_login_authentication(Username, [{password, Password}]) of
        {refused, _Err} -> {error, notfound};
        {refused, _Format, _Arg} -> {error, notfound};
        {ok, AuthUser} -> {ok, {Ctx, AuthUser}}
    end.

%% Access token ---------------------------------------------------------------

associate_access_token(AccessToken, Context, AppContext) ->
    ok = rabbit_oauth2_storage:save_access_token(AccessToken, Context),
    {ok, AppContext}.

resolve_access_token(AccessToken, AppContext) ->
    case rabbit_oauth2_storage:lookup_access_token(AccessToken) of
        {ok, {_, Context}} -> {ok, {AppContext, Context}};
        {error, not_found} -> {error, notfound}
    end.

revoke_access_token(AccessToken, AppContext) ->
    ok = rabbit_oauth2_storage:remove_access_token(AccessToken),
    {ok, AppContext}.

%% Access code ----------------------------------------------------------------

associate_access_code(AccessCode, Context, AppContext) ->
    ok = rabbit_oauth2_storage:save_access_code(AccessCode, Context),
    {ok, AppContext}.

resolve_access_code(AccessCode, AppContext) ->
    case rabbit_oauth2_storage:lookup_access_code(AccessCode) of
        {ok, {_, Context}} -> {ok, {AppContext, Context}};
        {error, not_found} -> {error, notfound}
    end.

revoke_access_code(AccessCode, AppContext) ->
    ok = rabbit_oauth2_storage:remove_access_code(AccessCode),
    {ok, AppContext}.

%% Refresh token --------------------------------------------------------------

associate_refresh_token(RefreshToken, Context, AppContext) ->
    ok = rabbit_oauth2_storage:save_refresh_token(RefreshToken, Context),
    {ok, AppContext}.

resolve_refresh_token(RefreshToken, AppContext) ->
    case rabbit_oauth2_storage:lookup_refresh_token(RefreshToken) of
        {ok, {_, Context}} -> {ok, {AppContext, Context}};
        {error, not_found} -> {error, notfound}
    end.

revoke_refresh_token(RefreshToken, AppContext) ->
    ok = rabbit_oauth2_storage:remove_refresh_token(RefreshToken),
    {ok, AppContext}.

%% Scope ----------------------------------------------------------------------

verify_scope(RScope, Scope, AppContext) when is_list(RScope), is_list(Scope) -> 
    case Scope -- RScope of
        [] -> {ok, {AppContext, Scope}};
        _  -> {error, invalid_scope}
    end;
verify_scope(_, _, _) -> {error, invalid_scope}.

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

verify_client_scope({_, _, _, CScope}, Scope, Ctx) when is_list(CScope),
                                                        is_list(Scope)  ->
    case Scope -- CScope of
        [] -> {ok, {Ctx, Scope}};
        _  -> {error, invalid_scope}
    end;
verify_client_scope(_, _, _) -> {error, invalid_scope}.

%% Client ---------------------------------------------------------------------

authenticate_client({ClientId, Secret}, Ctx) -> 
    case rabbit_oauth2_storage:lookup_client(ClientId) of
        {ok, Client = {ClientId, Secret, _, _}} -> {ok, {Ctx, Client}};
        {ok, _}            -> {error, badsecret};
        {error, not_found} -> {error, notfound}
    end.

get_client_identity(ClientId, Ctx) -> 
    case rabbit_oauth2_storage:lookup_client(ClientId) of
        {ok, Client} -> {ok, {Ctx, Client}};
        {error, not_found} -> {error, notfound}
    end.

get_redirection_uri({ClientId, Secret}, Ctx) -> 
    case rabbit_oauth2_storage:lookup_client(ClientId) of
        {ok, {ClientId, Secret, RedirUrl, _}} -> {ok, {Ctx, RedirUrl}};
        _ -> {error, notfound}
    end.


verify_redirection_uri({_, _, RedirUrl, _}, RedirUrl, Ctx) -> {ok, Ctx};
verify_redirection_uri(_, _, _)                            -> {error, mismatch}.

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
            case Kind == ignore orelse Permission == ignore orelse Name == [] of
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


