-module(rabbit_auth_backend_oauth_app).


-behaviour(application).
-export([start/2, stop/1, reset_dispatcher/1]).

-behaviour(supervisor).
-export([init/1]).

-define(CONTEXT, rabbit_oauth).

start(_Type, _StartArgs) ->
    {ok, AuthServer} = application:get_env(rabbitmq_auth_backend_oauth, 
                                           auth_server),
    maybe_register_context(AuthServer, []),
    supervisor:start_link({local,?MODULE},?MODULE,[]).

stop(_State) ->
    unregister_context(),
    ok.

%% At the point at which this is invoked we have both newly enabled
%% apps and about-to-disable apps running (so that
%% rabbit_mgmt_reset_handler can look at all of them to find
%% extensions). Therefore we have to explicitly exclude
%% about-to-disable apps from our new dispatcher.
reset_dispatcher(IgnoreApps) ->
    unregister_context(),
    {ok, AuthServer} = application:get_env(rabbitmq_auth_backend_oauth, 
                                           auth_server),
    maybe_register_context(AuthServer, IgnoreApps).

maybe_register_context(undefined, _IgnoreApps)  -> ok;
maybe_register_context([], _IgnoreApps)         -> ok;
maybe_register_context({AuthServerType, Listener}, _IgnoreApps) ->
    {Route, Description} = case AuthServerType of
        internal -> 
            {[{'_', [{"/oauth", rabbit_oauth2_auth, []}]}], 
             "RabbitMQ Oauth2 auth server"};
        external ->
            {[{'_', [{"/access_token", rabbit_oauth2_access_token, []}]}],
             "RabbitMQ Oauth2 access token endpoint"}
    end,
    rabbit_web_dispatch:register_context_handler(
        ?CONTEXT, Listener, "", 
        cowboy_router:compile(Route), Description).

unregister_context() ->
    rabbit_web_dispatch:unregister_context(?CONTEXT).

log_startup(Listener) ->
    rabbit_log:info("Oauth2 auth server started. Port: ~w~n", [port(Listener)]).

port(Listener) ->
    proplists:get_value(port, Listener).

init([]) ->
    {ok, {{one_for_one,3,10},[]}}.
