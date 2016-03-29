-module(rabbit_oauth2_auth).

-export([
         init/3
        ,rest_init/2
        ,allowed_methods/2
        ]).

-export([
         content_types_provided/2
        ,content_types_accepted/2
        ]).

-export([
         process_post/2
        ,process_get/2
        ]).

-export([binary_join/2]).

%%%===================================================================
%%% Cowboy callbacks
%%%===================================================================

init(_Transport, _Req, _Opts) ->
    %% Compile the DTL template used for the authentication
    %% form in the implicit grant flow.
    {upgrade, protocol, cowboy_rest}.

rest_init(Req, _Opts) ->
    {ok, Req, undefined_state}.

content_types_provided(Req, State) ->
    {[{{<<"text">>, <<"html">>, []}, process_get}], Req, State}.

content_types_accepted(Req, State) ->
    {[{{<<"application">>, <<"json">>, []}, process_post},
        {{<<"application">>, <<"x-www-form-urlencoded">>, []}, process_post}],
    Req, State}.

allowed_methods(Req, State) ->
    {[<<"POST">>, <<"GET">>], Req, State}.

process_post(Req, State) ->
    {ok, Params, Req2} = cowboy_req:body_qs(Req),
    {ok, Reply} =
        case proplists:get_value(<<"grant_type">>, Params) of
            <<"password">> ->
                process_password_grant(Req2, Params);
            <<"client_credentials">> ->
                process_client_credentials_grant(Req2, Params);
            <<"authorization_code">> ->
                process_authorization_token_grant(Req2, Params);
            undefined ->
                case proplists:get_value(<<"response_type">>, Params) of
                    RT when RT == <<"token">>; RT == <<"authorization_code">> ->
                        process_authorization_grant(Req2, RT, Params);
                    _ -> 
                        cowboy_req:reply(400, [], <<"Bad Request.">>, Req2)
                end;
            _ ->
                cowboy_req:reply(400, [], <<"Bad Request.">>, Req2)
        end,
    {halt, Reply, State}.

process_get(Req, State) ->
    {QsVals, Req2} = cowboy_req:qs_vals(Req),
    ResponseType = proplists:get_value(<<"response_type">>, QsVals),
    {ok, Reply} =
        case ResponseType of
            RT when RT == <<"token">>; RT == <<"authorization_code">> ->
                Params = lists:filter(
                    fun({K, _V}) -> 
                        lists:member(K, [<<"client_id">>,
                                         <<"redirect_uri">>,
                                         <<"scope">>,
                                         <<"state">>])
                    end,
                    QsVals),
                show_authorisation_form(Req2, ResponseType, Params);
            _ ->
                JSON = mochijson2:encode({struct, [{error,  <<"unsupported_response_type">>}]}),
                cowboy_req:reply(400, [], JSON, Req2)
        end,
    {halt, Reply, State}.

%%%===================================================================
%%% Grant type handlers
%%%===================================================================

process_password_grant(Req, Params) ->
    Username = proplists:get_value(<<"username">>, Params),
    Password = proplists:get_value(<<"password">>, Params),
    Scope    = get_scope(Params),
    AuthResult = oauth2:authorize_password({Username, Password}, Scope, []),
    Response = issue_token(AuthResult),
    reply(Response, Req).

process_client_credentials_grant(Req, Params) ->
    case cowboy_req:header(<<"authorization">>, Req) of
        {<<"Basic ", Credentials/binary>>, Req2} ->
            [Id, Secret] = binary:split(base64:decode(Credentials), <<":">>),
            Scope = get_scope(Params),
            AuthResult = oauth2:authorize_client_credentials({Id, Secret}, Scope, []),
            Response = issue_token(AuthResult),
            reply(Response, Req2);
        _ -> cowboy_req:reply(401, Req)
    end.

show_authorisation_form(Req, ResponseType, Params) ->
    State       = proplists:get_value(<<"state">>, Params),
    Scope       = get_scope(Params),
    ClientId    = proplists:get_value(<<"client_id">>, Params),
    RedirectUri = proplists:get_value(<<"redirect_uri">>, Params),
    %% Pass the scope, state and redirect URI to the browser
    %% as hidden form parameters, allowing them to "propagate"
    %% to the next stage.
    case ClientId == undefined of
        true ->
            cowboy_req:reply(400, [], <<"Bad Request.">>, Req);
        false ->
            {ok, Html} = auth_form_dtl:render([{redirect_uri, RedirectUri},
                                               {client_id, ClientId},
                                               {state, State},
                                               {scope, binary_join(Scope, <<" ">>)},
                                               {response_type, ResponseType}]),
            cowboy_req:reply(200, [], Html, Req)
    end.

% Process response from auth form.
% ResponseType coud be <<"token">> for implicit grant
% or <<"authorization_code">> for authorisation code grant 
process_authorization_grant(Req, ResponseType, Params) ->
    ClientId    = proplists:get_value(<<"client_id">>, Params),
    RedirectUri = proplists:get_value(<<"redirect_uri">>, Params),
    Username    = proplists:get_value(<<"username">>, Params),
    Password    = proplists:get_value(<<"password">>, Params),
    State       = proplists:get_value(<<"state">>, Params),
    Scope       = get_scope(Params),

    ExtraParams = [{<<"state">>, State}],
    AuthResult = oauth2:authorize_code_request({Username, Password}, 
                                               ClientId, 
                                               RedirectUri, Scope, []),
    Response = case ResponseType of
        <<"token">>              -> issue_token(AuthResult);
        <<"authorization_code">> -> issue_code(AuthResult)
    end,
    redirect(RedirectUri, Response, ExtraParams, Req).
    
process_authorization_token_grant(Req, Params) ->
    ClientId    = proplists:get_value(<<"client_id">>, Params),
    RedirectUri = proplists:get_value(<<"redirect_uri">>, Params),
    Code        = proplists:get_value(<<"code">>, Params),
    AuthResult = oauth2:authorize_code_grant(ClientId, Code, RedirectUri, []),
    Response = issue_token(AuthResult),
    reply(Response, Req).


%%%===================================================================
%%% Internal functions
%%%===================================================================

refresh_token_grant() ->
    application:get_env(rabbitmq_auth_backend_oauth, 
                        grant_rerfesh_token, 
                        false).

issue_token({ok, {_, Auth}}) ->
    TokenResponse = case refresh_token_grant() of
        true  -> oauth2:issue_token_and_refresh(Auth, []);
        false -> oauth2:issue_token(Auth, [])
    end,
    case TokenResponse of
        {ok, {_, TokenResp}} -> {ok, TokenResp};
        {error, _} = Err     -> Err
    end;
issue_token({error, Err}) ->
    {error, Err}.

issue_code({ok, {_, Auth}}) ->
    case oauth2:issue_code(Auth, []) of
        {ok, {_, CodeResp}} -> {ok, CodeResp};
        {error, _} = Err    -> Err
    end;
issue_code({error, Err}) ->
    {error, Err}.

reply({ok, Response}, Req) ->
    Proplist = lists:keydelete(<<"resource_owner">>, 1, 
                               oauth2_response:to_proplist(Response)),
    cowboy_req:reply(200, [], mochijson2:encode({struct, Proplist}), Req);
reply({error, Err}, Req) ->
    cowboy_req:reply(400, [], 
                     mochijson2:encode({struct, [{<<"error">>, Err}]}), 
                     Req).

redirect(RedirectUri, {ok, Response}, Extra, Req) ->
    Params = oauth2_response:to_proplist(Response) ++ Extra,
    redirect(RedirectUri, Params, Req);
redirect(RedirectUri, {error, Err}, Extra, Req) ->
    Params = [{<<"error">>, Err} | Extra],
    redirect(RedirectUri, Params, Req).

redirect(RedirectUri, Params, Req) when is_list(Params) ->
    BinParams = lists:map(
        fun ({K,V}) when is_integer(V) -> {K, integer_to_binary(V)};
            ({K,V}) when is_atom(V)    -> {K, atom_to_binary(V, utf8)};
            ({K,V}) when is_binary(V)  -> {K,V}
        end,
        Params),
    Frag = cow_qs:qs(BinParams),
    Req1 = cowboy_req:set_resp_header(<<"location">>, 
                                      <<RedirectUri/binary, "#", Frag/binary>>, 
                                      Req),
    cowboy_req:reply(302, [], <<>>, Req1).


get_scope(Params) ->
    binary:split(proplists:get_value(<<"scope">>, Params, <<>>), 
                 <<" ">>, 
                 [global]).

binary_join([], _) -> <<>>;
binary_join([H], _) -> H;
binary_join([H1, H2 | T], Sep) ->
    binary_join([<<H1/binary, Sep/binary, H2/binary>> | T], Sep).







