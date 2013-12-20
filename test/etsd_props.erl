-module(etsd_props).
-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(M, etsdangerous).
-define(SLEEPTIME, 3). %% seconds

%% Generators.

nonempty_binary() ->
    ?LET(Len, pos_integer(),
         binary(Len)).

long_age() ->
    oneof([infinity, integer(2, inf)]).

%% Properties.

prop_signer_reversible() ->
    ?FORALL({Bin, Key, Salt},
            {binary(), binary(), binary()},
            begin
                S = ?M:signer(Key, Salt),
                {ok, {UnsignedBin, undefined}} = ?M:unsign(S, ?M:sign(S, Bin)),
                equals(Bin, UnsignedBin)
            end).

prop_ts_signer_reversible() ->
    ?FORALL({Bin, Key, MaxAge, Salt},
            {binary(), binary(), long_age(), binary()},
            begin
                S = ?M:ts_signer(Key, MaxAge, Salt),
                Time = calendar:universal_time(),
                {ok, {UnsignedBin, SignTime}} = ?M:unsign(S, ?M:sign(S, Bin)),
                equals({Bin, Time}, {UnsignedBin, SignTime})
            end).

prop_signer_bad_signature() ->
    ?FORALL({Bin, Key, Salt, Extra},
            {binary(), binary(), binary(), nonempty_binary()},
            begin
                S = ?M:signer(Key, Salt),
                SignedBin = ?M:sign(S, Bin),
                ChangedBin = <<Extra/binary, SignedBin/binary>>,
                {error, bad_signature} == ?M:unsign(S, ChangedBin)
            end).

prop_ts_signer_bad_signature() ->
    ?FORALL({Bin, Key, MaxAge, Salt, Extra},
            {binary(), binary(), long_age(), binary(), nonempty_binary()},
            begin
                S = ?M:ts_signer(Key, MaxAge, Salt),
                SignedBin = ?M:sign(S, Bin),
                ChangedBin = <<Extra/binary, SignedBin/binary>>,
                equals({error, bad_signature}, ?M:unsign(S, ChangedBin))
            end).

prop_ts_signer_expires() ->
    numtests(
      10,
      ?FORALL({Bin, Key, MaxAge},
              {binary(), binary(), integer(1, ?SLEEPTIME * 2)},
              begin
                  S = ?M:ts_signer(Key, MaxAge),
                  Signed = ?M:sign(S, Bin),
                  SignTime = calendar:universal_time(),
                  timer:sleep(?SLEEPTIME * 1000),
                  Unsigned = ?M:unsign(S, Signed),
                  case MaxAge >= ?SLEEPTIME of
                      true  -> equals(Unsigned, {ok, {Bin, SignTime}});
                      false -> equals(Unsigned, {error, signature_expired})
                  end
              end)).

%% Suite.

proper_test_() ->
    {timeout, 600,
     ?_assertEqual([], proper:module(etsd_props, [{to_file, user},
                                                  {numtests, 5000}]))}.
