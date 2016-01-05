-module(rabbit_oauth2_auth).
-include_lib("rabbit_common/include/rabbit.hrl").


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
    {[{{<<"text">>, <<"json">>, []}, process_get}], Req, State}.

content_types_accepted(Req, State) ->
    {[{{<<"application">>, <<"json">>, []}, process_post},
        {{<<"application">>, <<"x-www-form-urlencoded">>, []}, process_post}],
    Req, State}.

allowed_methods(Req, State) ->
    {[<<"POST">>, <<"GET">>], Req, State}.

process_post(Req, State) ->
    {ok, Params, Req2} = cowboy_req:body_qs(Req),
    {ok, Reply} =
        case lists:max([proplists:get_value(K, Params)
                        || K <- [<<"grant_type">>, <<"response_type">>]]) of
            <<"password">> ->
                process_password_grant(Req2, Params);
            % <<"client_credentials">> ->
            %     process_client_credentials_grant(Req2, Params);
            % <<"token">> ->
            %     process_implicit_grant_stage2(Req2, Params);
            _ ->
                cowboy_req:reply(400, [], <<"Bad Request.">>, Req2)
        end,
    {halt, Reply, State}.

process_get(Req, State) ->
    {ResponseType, Req2} = cowboy_req:qs_val(<<"response_type">>, Req),
    {ok, Reply} =
        case ResponseType of
            % <<"token">> ->
            %     {Req3, Params} =
            %         lists:foldl(fun(Name, {R, Acc}) ->
            %                             {Val, R2} =
            %                                 cowboy_req:qs_val(Name, R),
            %                             {R2, [{Name, Val}|Acc]}
            %                     end,
            %                     {Req2, []},
            %                     [<<"client_id">>,
            %                      <<"redirect_uri">>,
            %                      <<"scope">>,
            %                      <<"state">>]),
            %     process_implicit_grant(Req3, Params);
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
            {ok, #auth_user{username = UserName}} = 
                oauth2_response:resource_owner(Response),
            PropList = oauth2_response:to_proplist(
                oauth2_response:resource_owner(Response, UserName)),
            rabbit_log:info("Response ~p",[PropList]),
            {200, mochijson2:encode({struct, PropList})}
    end,
  cowboy_req:reply(Code, [], JSON, Req).















