-module(rabbit_auth_backend_oauth_app).


-behaviour(application).
-export([start/2, stop/1]).

-behaviour(supervisor).
-export([init/1]).

-define(CONTEXT, rabbit_oauth).

start(_Type, _StartArgs) ->
    {ok, AuthServer} = application:get_env(rabbitmq_auth_backend_oauth, 
                                           auth_server),
    case AuthServer of
        undefined -> ok;
        [] -> ok;
        Config ->
            {_, Listener} = lists:keyfind(listener, 1, AuthServer),
            register_context(Listener, []),
            log_startup(Listener)
    end,
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
    {ok, Listener} = application:get_env(rabbitmq_auth_backend_oauth, listener),
    register_context(Listener, IgnoreApps).

register_context(Listener, IgnoreApps) ->
    rabbit_web_dispatch:register_context_handler(
        ?CONTEXT, Listener, "",
        cowboy_router:compile([{'_', [{"/oauth", rabbit_oauth2_auth, []}]}]),
        "RabbitMQ Oauth2 auth server").

unregister_context() ->
    rabbit_web_dispatch:unregister_context(?CONTEXT).

log_startup(Listener) ->
    rabbit_log:info("Oauth2 auth server started. Port: ~w~n", [port(Listener)]).

port(Listener) ->
    proplists:get_value(port, Listener).

init([]) ->
    {ok, {{one_for_one,3,10},[]}}.
