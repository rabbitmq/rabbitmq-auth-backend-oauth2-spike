-module(mock_transport).

-export([name/0, send/2]).

name() -> mock.

send(_,_) -> ok.