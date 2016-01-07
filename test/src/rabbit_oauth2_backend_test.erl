-module(rabbit_oauth2_backend_test).

-compile(export_all).
-include_lib("eunit/include/eunit.hrl").
-include_lib("rabbit_common/include/rabbit.hrl").

standalone_tests() -> 
    parse_scope_test(),
    scope_permissions_test(),
    passed.

broker_tests() ->
    save_load_token_test(),
    revoke_token_test(),
    expire_token_test(),
    token_permission_test(),
    passed.

parse_scope_test() ->
    Scopes = [
        % VHost_Kind_Permission_Name
        {<<"vhost_q_conf_foo">>, {<<"vhost">>, queue, <<"foo">>, configure}},
        {<<"vhost_q_write_foo">>, {<<"vhost">>, queue, <<"foo">>, write}},
        {<<"vhost_q_read_foo">>, {<<"vhost">>, queue, <<"foo">>, read}},
        {<<"vhost_ex_conf_foo">>, {<<"vhost">>, exchange, <<"foo">>, configure}},
        {<<"vhost_ex_write_foo">>, {<<"vhost">>, exchange, <<"foo">>, write}},
        {<<"vhost_ex_read_foo">>, {<<"vhost">>, exchange, <<"foo">>, read}},
        {<<"vhost_t_write_foo">>, {<<"vhost">>, topic, <<"foo">>, write}},
        % Name can contain '_'
        {<<"vhost_q_conf_foo_bar_baz">>, {<<"vhost">>, queue, <<"foo_bar_baz">>, configure}},
        % Vhost cannot contain '_'
        {<<"vhost_foo_q_conf_foo_bar">>, ignore},
        % Vhost and name can contain different characters
        {<<"vhost.com/foo_q_conf_foo.bar,baz">>, {<<"vhost.com/foo">>, queue, <<"foo.bar,baz">>, configure}},
        % Kind and Permission should be valid
        {<<"vhost_qu_conf_name">>, ignore},
        {<<"vhost_q_noconf_name">>, ignore},
        % There should be all parts
        {<<"vhost_q_conf">>, ignore},
        {<<"vhost_q_name">>, ignore},
        {<<"q_conf_name">>, ignore},
        % '/' for default host
        {<<"/_q_conf_foo">>, {<<"/">>, queue, <<"foo">>, configure}},
        % Utf?
        {<<"/_q_conf_ПиуПиу"/utf8>>, {<<"/">>, queue, <<"ПиуПиу"/utf8>>, configure}}  
    ],
    lists:foreach(
        fun({Scope, Result}) ->
            case rabbit_oauth2_backend:parse_scope_el(Scope) of
                ignore ->
                    Result = ignore;
                {#resource{ virtual_host = VHost, kind = Kind, name = Name }, 
                 Permission, Scope} ->
                    Result = {VHost, Kind, Name, Permission}
            end
        end,
        Scopes).
save_load_token_test() ->
    {error, notfound} = rabbit_oauth2_backend:lookup(<<"token">>),
    ok = rabbit_oauth2_backend:save(<<"token1">>, [{<<"scope">>, [<<"FOO">>]}]),
    {ok, [{<<"scope">>, [<<"FOO">>]}]} = rabbit_oauth2_backend:lookup(<<"token1">>),
    {error, notfound} = rabbit_oauth2_backend:lookup(<<"token">>),
    TimeSec = time_compat:os_system_time(seconds),
    ok = rabbit_oauth2_backend:add_access_token(<<"token2">>, [<<"foo">>, <<"bar">>], 100, TimeSec),
    Context = [{<<"scope">>, [<<"foo">>, <<"bar">>]}, {<<"expiry_time">>, 100 + TimeSec}],
    {ok, {[], Context}} = rabbit_oauth2_backend:resolve_access_token(<<"token2">>, []).

revoke_token_test() ->
    TimeSec = time_compat:os_system_time(seconds),
    ok = rabbit_oauth2_backend:add_access_token(<<"token3">>, [<<"foo">>, <<"bar">>], 100, TimeSec),
    {ok, foo} = rabbit_oauth2_backend:revoke_access_token(<<"token3">>, foo),
    {error, access_denied} = oauth2:verify_access_token(<<"token3">>, []).

expire_token_test() ->
    TimeSec = time_compat:os_system_time(seconds),
    ok = rabbit_oauth2_backend:add_access_token(<<"token3">>, [<<"foo">>, <<"bar">>], 1, TimeSec),
    timer:sleep(1500),
    {error, access_denied} = oauth2:verify_access_token(<<"token3">>, []).    

scope_permissions_test() ->
    Examples = [
        % VHost_Kind_Permission_Name
        {<<"vhost_q_conf_foo">>, {<<"vhost">>, queue, <<"foo">>, configure}},
        {<<"vhost_q_write_foo">>, {<<"vhost">>, queue, <<"foo">>, write}},
        {<<"vhost_q_read_foo">>, {<<"vhost">>, queue, <<"foo">>, read}},
        {<<"vhost_ex_conf_foo">>, {<<"vhost">>, exchange, <<"foo">>, configure}},
        {<<"vhost_ex_write_foo">>, {<<"vhost">>, exchange, <<"foo">>, write}},
        {<<"vhost_ex_read_foo">>, {<<"vhost">>, exchange, <<"foo">>, read}},
        {<<"vhost_t_write_foo">>, {<<"vhost">>, topic, <<"foo">>, write}},
        {<<"vhost_q_conf_foo_bar_baz">>, {<<"vhost">>, queue, <<"foo_bar_baz">>, configure}},
        {<<"vhost.com/foo_q_conf_foo.bar,baz">>, {<<"vhost.com/foo">>, queue, <<"foo.bar,baz">>, configure}},
        {<<"/_q_conf_foo">>, {<<"/">>, queue, <<"foo">>, configure}},
        {<<"/_q_conf_ПиуПиу"/utf8>>, {<<"/">>, queue, <<"ПиуПиу"/utf8>>, configure}}  
    ],
    lists:foreach(
        fun(Example) ->
            {Scope, {Vhost, Kind, Name, Permission}} = Example,
            Resource = #resource{ virtual_host = Vhost, kind = Kind, name = Name},
            Context = [{<<"scope">>, [Scope]}],
            true = rabbit_oauth2_backend:vhost_access(Vhost, Context),
            true = rabbit_oauth2_backend:resource_access(Resource, Permission, Context)
        end,
        Examples).


token_permission_test() ->
    ok = rabbit_oauth2_backend:add_access_token(<<"token4">>, [<<"/_q_conf_foo">>], 1000, TimeSec),
    {refused, _} = rabbit_auth_backend_oauth:user_login_authentication(<<"token3">>, []),
    AuthUser = #auth_user{ username = Token } = 
        rabbit_auth_backend_oauth:user_login_authentication(<<"token4">>, []),
    {ok, none} = rabbit_auth_backend_oauth:user_login_authorisation(<<"token4">>),
    true = rabbit_auth_backend_oauth:check_vhost_access(AuthUser, <<"/">>),
    false = rabbit_auth_backend_oauth:check_vhost_access(AuthUser, <<"other">>),
    true = rabbit_auth_backend_oauth:check_resource_access(
        AuthUser,
        #resource{ virtual_host = <<"/">>, kind = queue, name = <<"foo">>},
        configure),
    false = rabbit_auth_backend_oauth:check_resource_access(
        AuthUser,
        #resource{ virtual_host = <<"other">>, kind = queue, name = <<"foo">>},
        configure),
    false = rabbit_auth_backend_oauth:check_resource_access(
        AuthUser,
        #resource{ virtual_host = <<"/">>, kind = queue, name = <<"foo1">>},
        configure),
    false = rabbit_auth_backend_oauth:check_resource_access(
        AuthUser,
        #resource{ virtual_host = <<"/">>, kind = exchange, name = <<"foo">>},
        configure),
    false = rabbit_auth_backend_oauth:check_resource_access(
        AuthUser,
        #resource{ virtual_host = <<"/">>, kind = queue, name = <<"foo">>},
        write).

