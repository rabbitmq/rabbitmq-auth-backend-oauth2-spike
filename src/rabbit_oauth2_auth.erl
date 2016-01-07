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
                    RT when RT == <<"token">>; RT == <<"code">> ->
                        process_authorization_grant(Req2, RT, Params);
                    _ -> 
                        cowboy_req:reply(400, [], <<"Bad Request.">>, Req2)
                end;
            _ ->
                cowboy_req:reply(400, [], <<"Bad Request.">>, Req2)
        end,
    {halt, Reply, State}.

process_get(Req, State) ->
    {ResponseType, Req2} = cowboy_req:qs_val(<<"response_type">>, Req),
    {ok, Reply} =
        case ResponseType of
            RT when RT == <<"token">>; RT == <<"code">> ->
                {Req3, Params} =
                    lists:foldl(fun(Name, {R, Acc}) ->
                                        {Val, R2} =
                                            cowboy_req:qs_val(Name, R),
                                        {R2, [{Name, Val}|Acc]}
                                end,
                                {Req2, []},
                                [<<"client_id">>,
                                 <<"redirect_uri">>,
                                 <<"scope">>,
                                 <<"state">>]),
                show_authorisation_form(Req3, ResponseType, Params);
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
    Scope    = binary:split(proplists:get_value(<<"scope">>, Params, <<"">>), 
                            <<" ">>, 
                            [global]),
    Auth = oauth2:authorize_password({Username, Password}, Scope, []),
    issue_token(Auth, Req).

process_client_credentials_grant(Req, Params) ->
    {<<"Basic ", Credentials/binary>>, Req2} =
        cowboy_req:header(<<"authorization">>, Req),
    [Id, Secret] = binary:split(base64:decode(Credentials), <<":">>),
    Scope    = binary:split(proplists:get_value(<<"scope">>, Params, <<"">>), 
                            <<" ">>, 
                            [global]),
    {ok, {_Ctx, Auth}} = oauth2:authorize_client_credentials({Id, Secret}, 
                                                             Scope, 
                                                             []),
    issue_token(Auth, Req2).

show_authorisation_form(Req, ResponseType, Params) ->
    State       = proplists:get_value(<<"state">>, Params),
    Scope       = proplists:get_value(<<"scope">>, Params, <<>>),
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
                                               {scope, Scope},
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
    Scope       = proplists:get_value(<<"scope">>, Params),
    case oauth2:authorize_password({Username, Password}, ClientId, RedirectUri, Scope, []) of
        {ok, {_, Auth}} ->
            {ok, {_, Response}} = case ResponseType of
                <<"token">>              -> oauth2:issue_token(Auth, []);
                <<"authorization_code">> -> oauth2:issue_code(Auth, [])
            end,
            Props = [{<<"state">>, State}
                     | oauth2_response:to_proplist(Response)],
            redirect_resp(RedirectUri, Props, Req);
        {error, Reason} ->
            redirect_resp(RedirectUri,
                          [{<<"error">>, atom_to_binary(Reason, utf8)},
                           {<<"state">>, State}],
                          Req)
    end.

process_authorization_token_grant(Req, Params) ->
    ClientId    = proplists:get_value(<<"client_id">>, Params),
    RedirectUri = proplists:get_value(<<"redirect_uri">>, Params),
    Code        = proplists:get_value(<<"code">>, Params),
    issue_token(oauth2:authorize_code_grant(ClientId, Code, RedirectUri, []), 
                Req).


%%%===================================================================
%%% Internal functions
%%%===================================================================

issue_token({ok, {_AppCtx, Auth}}, Req) ->
    emit_response(oauth2:issue_token(Auth, []), Req);
issue_token(Error, Req) ->
    emit_response(Error, Req).

emit_response(AuthResult, Req) ->
  {Code, JSON} =
    case AuthResult of
        {error, Reason} ->
            {400, mochijson2:encode({struct, [{error, atom_to_binary(Reason, utf8)}]})};
        {ok, {_,Response}} ->
            PropList = lists:keydelete(<<"resource_owner">>, 1,
                                       oauth2_response:to_proplist(Response)),
            {200, mochijson2:encode({struct, PropList})}
    end,
  cowboy_req:reply(Code, [], JSON, Req).

redirect_resp(RedirectUri, FragParams, Req) ->
    Frag = binary_join([<<(cow_qs:urlencode(K))/binary, "=",
                          (cow_qs:urlencode(V))/binary>>
                            || {K, V} <- FragParams],
                       <<"&">>),
    Header = [{<<"location">>, <<RedirectUri/binary, "#", Frag/binary>>}],
    cowboy_req:reply(302, Header, <<>>, Req).

binary_join([H], _Sep) ->
    <<H/binary>>;
binary_join([H|T], Sep) ->
    <<H/binary, Sep/binary, (binary_join(T, Sep))/binary>>;
binary_join([], _Sep) ->
    <<>>.













