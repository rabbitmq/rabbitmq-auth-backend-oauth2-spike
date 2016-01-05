-module(rabbit_oauth2_access_token).

-export([
         init/3
        ,rest_init/2
        ,allowed_methods/2
        ]).

-export([content_types_accepted/2]).

-export([process_post/2]).


%%%===================================================================
%%% Cowboy callbacks
%%%===================================================================

init(_Transport, _Req, _Opts) ->
    %% Compile the DTL template used for the authentication
    %% form in the implicit grant flow.
    {upgrade, protocol, cowboy_rest}.

rest_init(Req, _Opts) ->
    {ok, Req, undefined_state}.

content_types_accepted(Req, State) ->
    {[{{<<"application">>, <<"json">>, []}, process_post},
        {{<<"application">>, <<"x-www-form-urlencoded">>, []}, process_post}],
    Req, State}.

allowed_methods(Req, State) ->
    {[<<"POST">>], Req, State}.

process_post(Req, State) ->
    {ok, Params, Req2} = cowboy_req:body_qs(Req),
    Token     = proplists:get_value(<<"access_token">>, Params),
    Scope     = binary:split(proplists:get_value(<<"scope">>, Params), 
                             <<" ">>, [global]),
    ExpiresIn = binary_to_integer(proplists:get_value(<<"expires_in">>, 
                                  Params)),
    CreatedAt = proplists:get_value(<<"created_at">>, Params, 
                                    time_compat:os_system_time(seconds)),
    % TODO: default scope
    {ok, Reply} = case Token == undefined 
                       orelse Scope == undefined 
                       orelse ExpiresIn == undefined of
        true  -> cowboy_req:reply(400, [], <<"Bad Request.">>, Req2);
        false ->
            ok = rabbit_oauth2_backend:add_access_token(Token, 
                                                        Scope, 
                                                        ExpiresIn, 
                                                        CreatedAt),
            cowboy_req:reply(200, [], <<"Ok">>, Req2)
    end,
    {halt, Reply, State}.