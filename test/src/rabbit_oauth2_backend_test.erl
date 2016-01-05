-module(rabbit_oauth2_backend_test).

-compile(export_all).
-include_lib("eunit/include/eunit.hrl").
-include_lib("rabbit_common/include/rabbit.hrl").

test() -> parse_scope_test().

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
% save_load_token_test() ->
%     ...

% revoke_token_test() ->
%     ...

% expire_token_test() ->
%     ...

% token_permissions_test() ->
%     ...