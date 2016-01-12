-module(rabbit_oauth2_auth_test).

-compile(export_all).

tests() ->
    test_get(),
    test_grant_type(),
    test_resp_type(),
    % test_refresh(),
    passed.


test_get() ->
    % TODO: error cases.
    % There will be same result (auth form) for each response type
    RespTypes   = [<<"token">>, <<"authorization_code">>],
    ClientId    = <<"foo">>, 
    RedirectUri = <<"http://example.com">>, 
    Scope       = <<"sope_scope other_scope">>, 
    State       = <<"random_state">>,
    Params = [{<<"client_id">>, ClientId}, 
              {<<"redirect_uri">>, RedirectUri}, 
              {<<"scope">>, Scope},
              {<<"state">>, State}],
    lists:foreach(fun(RespType) ->
        {ok, {200, RespBody}} = http_get(Params ++ 
                                         [{<<"response_type">>, RespType}]),
        <<"<!DOCTYPE html>", _/binary>> = RespBody,
        {_,_} = binary:match(RespBody, 
            <<"<input type=\"hidden\" name=\"response_type\" value=\"", 
            RespType/binary, 
            "\" />">>),
        {_,_} = binary:match(RespBody, 
            <<"<input type=\"hidden\" name=\"client_id\" value=\"", 
            ClientId/binary, 
            "\" />">>),
        {_,_} = binary:match(RespBody, 
            <<"<input type=\"hidden\" name=\"redirect_uri\" value=\"", 
            RedirectUri/binary, 
            "\" />">>),
        {_,_} = binary:match(RespBody, 
            <<"<input type=\"hidden\" name=\"scope\" value=\"", 
            Scope/binary, 
            "\" />">>),
        {_,_} = binary:match(RespBody, 
            <<"<input type=\"hidden\" name=\"state\" value=\"", 
            State/binary, 
            "\" />">>)
    end,
    RespTypes).

test_grant_type() ->
    Scope = <<"/_q_conf_foo /_ex_conf_bar">>,
    Scopes = binary:split(Scope, <<" ">>, [global]),
    ClientId = <<"foo">>,
    ClientSecret = <<"bar">>,
    RedirectUri = <<"http://example.com">>,
    Username = <<"guest">>,
    Password = <<"guest">>,
    ClientAuth = base64:encode_to_string(<<ClientId/binary, ":", 
                                           ClientSecret/binary>>),
    ok = create_client(ClientId, ClientSecret, RedirectUri, Scopes),
    {ok, AuthCode} = create_code(ClientId, ClientSecret, Scopes),
    GrantTypes = [
        {<<"password">>, 
            [{<<"username">>, Username},
             {<<"password">>, Password}, 
             {<<"scope">>, Scope}], 
            []}
        ,{<<"client_credentials">>, 
            [{<<"scope">>, Scope}], 
            [{"Authorization", "Basic " ++ ClientAuth}]}
        ,{<<"authorization_code">>,
            [{<<"client_id">>, ClientId},
             {<<"redirect_uri">>, RedirectUri},
             {<<"code">>, AuthCode}],
            []}
        ],
    lists:foreach(
        fun({CodeGrant, Params, Headers}) ->
            {ok, {200, Result, _}} = http_post([{<<"grant_type">>, CodeGrant} 
                                                | Params], Headers),
            {struct, ResultData} = mochijson2:decode(Result),
            {<<"access_token">>, AccessToken}  = proplists:lookup(<<"access_token">>, ResultData),
            {<<"expires_in">>,   Expiry}       = proplists:lookup(<<"expires_in">>, ResultData),
            {<<"scope">>,        Scope}        = proplists:lookup(<<"scope">>, ResultData),
            {<<"token_type">>,   <<"bearer">>} = proplists:lookup(<<"token_type">>, ResultData)
        end,
        GrantTypes).

test_resp_type() ->
    Scope = <<"/_q_conf_foo /_ex_conf_bar">>,
    Scopes = binary:split(Scope, <<" ">>, [global]),
    ClientId = <<"foo">>,
    ClientSecret = <<"bar">>,
    RedirectUri = <<"http://example.com">>,
    Username = <<"guest">>,
    Password = <<"guest">>,
    State = <<"Some state">>,

    RespTypes = [<<"token">>, <<"authorization_code">>],
    Params = [{<<"client_id">>, ClientId},
              {<<"redirect_uri">>, RedirectUri},
              {<<"username">>, Username},
              {<<"password">>, Password},
              {<<"state">>, State},
              {<<"scope">>, Scope}],
    lists:foreach(
        fun(RespType) ->
            {ok, {302, _, Headers}} = http_post([{<<"response_type">>, RespType} 
                                             | Params], []),
            {"location", Location} = proplists:lookup("location", Headers),
            [Url, Qs] = string:tokens(Location, "#"),
            RedirectUri = list_to_binary(Url),
            ResultData = cow_qs:parse_qs(list_to_binary(Qs)),
            case RespType of
                <<"token">> ->
                    {<<"access_token">>, AccessToken}  = proplists:lookup(<<"access_token">>, ResultData),
                    {<<"expires_in">>,   Expiry}       = proplists:lookup(<<"expires_in">>, ResultData),
                    {<<"scope">>,        Scope}        = proplists:lookup(<<"scope">>, ResultData),
                    {<<"token_type">>,   <<"bearer">>} = proplists:lookup(<<"token_type">>, ResultData);
                <<"authorization_code">> ->
                    {<<"access_code">>, AccessToken}  = proplists:lookup(<<"access_code">>, ResultData),
                    {<<"expires_in">>,  Expiry}       = proplists:lookup(<<"expires_in">>, ResultData),
                    {<<"scope">>,       Scope}        = proplists:lookup(<<"scope">>, ResultData),
                    {<<"token_type">>,  <<"bearer">>} = proplists:lookup(<<"token_type">>, ResultData)
            end
        end,
        RespTypes).


create_client(ClientId, ClientSecret, RedirectUri, Scope) ->
    rabbit_oauth2_storage:save_client(ClientId, ClientSecret, RedirectUri, Scope).

create_code(ClientId, Secret, Scope) ->
    {ok, {n, Auth}} = oauth2:authorize_client_credentials({ClientId, Secret}, Scope, n),
    {ok, {n, CodeResp}} = oauth2:issue_code(Auth, n),
    {ok, Code} = oauth2_response:access_code(CodeResp).

http_get(Params) ->
    Qs = cow_qs:qs(Params),
    Url = <<"http://localhost:15672/oauth?", Qs/binary>>,
    {ok, {{_, Status, _}, _, Body}} = httpc:request(binary_to_list(Url)),
    {ok, {Status, list_to_binary(Body)}}.
        
http_post(Params, Headers) ->
    Qs = cow_qs:qs(Params),
    Url = "http://localhost:15672/oauth",
    {ok, {{_, Status, _}, RespHeaders, Body}} = httpc:request(post, {Url, Headers, "application/x-www-form-urlencoded", Qs}, [], []),
    {ok, {Status, list_to_binary(Body), RespHeaders}}.
