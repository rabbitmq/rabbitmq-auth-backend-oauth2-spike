-module(rabbit_oauth2_storage).

-export([
    save_client/4,
    save_access_code/2,
    save_access_token/2,
    save_refresh_token/2,

    lookup_client/1,
    lookup_access_code/1,
    lookup_access_token/1,
    lookup_refresh_token/1,

    remove_client/1,
    remove_access_code/1,
    remove_access_token/1,
    remove_refresh_token/1
]).

-export([setup_schema/0]).

-record(token, {
    token, 
    context
    }).

-record(client,{
    client_id,
    client_secret,
    redirect_uri,
    scope
    }).

-define(ACCESS_TOKEN_TABLE, rabbit_oauth2_access_token).
-define(ACCESS_CODE_TABLE, rabbit_oauth2_access_code).
-define(REFRESH_TOKEN_TABLE, rabbit_oauth2_refresh_token).
-define(CLIENT_TABLE, rabbit_oauth2_client).

setup_schema() ->
    mnesia:create_table(?ACCESS_TOKEN_TABLE,
                             [{attributes, record_info(fields, token)},
                              {record_name, token},
                              {type, set}]),
    mnesia:create_table(?REFRESH_TOKEN_TABLE,
                             [{attributes, record_info(fields, token)},
                              {record_name, token},
                              {type, set}]),
    mnesia:create_table(?CLIENT_TABLE,
                             [{attributes, record_info(fields, client)},
                              {record_name, client},
                              {type, set}]),
    mnesia:create_table(?ACCESS_CODE_TABLE,
                             [{attributes, record_info(fields, token)},
                              {record_name, token},
                              {type, set}]),
    mnesia:add_table_copy(?ACCESS_TOKEN_TABLE, node(), ram_copies),
    mnesia:add_table_copy(?REFRESH_TOKEN_TABLE, node(), ram_copies),
    mnesia:add_table_copy(?CLIENT_TABLE, node(), ram_copies),
    mnesia:add_table_copy(?ACCESS_CODE_TABLE, node(), ram_copies),

    mnesia:wait_for_tables([?ACCESS_TOKEN_TABLE,
                            ?REFRESH_TOKEN_TABLE,
                            ?CLIENT_TABLE,
                            ?ACCESS_CODE_TABLE], 30000).

save_client(ClientId, Secret, RedirUri, Scope) ->
    Client = #client{ 
        client_id = ClientId,
        client_secret = Secret,
        redirect_uri = RedirUri,
        scope = Scope},
    save(?CLIENT_TABLE, Client).

save_access_token(Token, Context) ->
    save_token(?ACCESS_TOKEN_TABLE, Token, Context).

save_refresh_token(Token, Context) ->
    save_token(?REFRESH_TOKEN_TABLE, Token, Context).

save_access_code(Code, Context) ->
    save_token(?ACCESS_CODE_TABLE, Code, Context).

save_token(Table, Token, Context) ->
    TokenRecord = #token{ token = Token, context = Context },
    save(Table, TokenRecord).

save(Table, Data) ->
     rabbit_misc:execute_mnesia_transaction(
        fun () ->
            ok = mnesia:write(Table, Data, write)
        end).


lookup_client(ClientId) ->
    case lookup(?CLIENT_TABLE, ClientId) of
        {error, not_found} -> {error, not_found};
        {ok, #client{client_secret = Secret, 
                     redirect_uri = RedirUri, 
                     scope = Scope}} ->
            {ok, {ClientId, Secret, RedirUri, Scope}}
    end.

lookup_access_token(Token) ->
    lookup_token(?ACCESS_TOKEN_TABLE, Token).

lookup_refresh_token(Token) ->
    lookup_token(?REFRESH_TOKEN_TABLE, Token).

lookup_access_code(Code) ->
    lookup_token(?ACCESS_CODE_TABLE, Code).

lookup_token(Table, Token) ->
    case lookup(Table, Token) of
        {error, not_found} -> {error, not_found};
        {ok, #token{context = Context}} ->
            {ok, {Token, Context}}
    end.

lookup(Table, Key) ->
    rabbit_misc:dirty_read({Table, Key}).

remove_client(ClientId) ->
    delete(?CLIENT_TABLE, ClientId).

remove_access_token(Token) ->
    delete(?ACCESS_TOKEN_TABLE, Token).

remove_refresh_token(Token) ->
    delete(?REFRESH_TOKEN_TABLE, Token).

remove_access_code(Code) ->
    delete(?ACCESS_CODE_TABLE, Code).

delete(Table, Key) ->
    rabbit_misc:execute_mnesia_transaction(
        fun() ->
            ok = mnesia:delete({Table, Key})
        end).


