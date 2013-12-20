-module(etsdangerous).
-define(DEFAULT_SALT_SIGNER, <<"etsdangerous.Signer">>).
-define(DEFAULT_SALT_TIMESTAMP_SIGNER, <<"etsdangerous.TimestampSigner">>).
-define(DEFAULT_MAX_AGE, infinity).
-define(DEFAULT_SEP, <<".">>).
-define(EPOCH, {{2011, 1, 1}, {0, 0, 0}}).

-ifdef(old_hash).
-define(SHA(Data), crypto:sha(Data)).
-define(SHA_MAC(Key, Data), crypto:sha_mac(Key, Data)).
-else.
-define(SHA(Data), crypto:hash(sha, Data)).
-define(SHA_MAC(Key, Data), crypto:hmac(sha, Key, Data)).
-endif.

-type age() :: infinity | pos_integer().

-record(signer, {type       :: untimed | {timed, age()},
                 secret_key :: binary(),
                 salt       :: binary(),
                 sep        :: binary()}).

-export([signer/1, signer/2, signer/3,
         ts_signer/2, ts_signer/3, ts_signer/4,
         get_signature/2, sign/2, unsign/2, validate/2]).

-spec signer(binary()) -> #signer{}.
signer(SecretKey) ->
    signer(SecretKey, ?DEFAULT_SALT_SIGNER, ?DEFAULT_SEP).

-spec signer(binary(), binary()) -> #signer{}.
signer(SecretKey, Salt) ->
    signer(SecretKey, Salt, ?DEFAULT_SEP).

-spec signer(binary(), binary(), binary()) -> #signer{}.
signer(SecretKey, Salt, Sep)
  when is_binary(SecretKey) andalso
       is_binary(Salt) andalso
       is_binary(Sep) ->
    #signer{type=untimed,
            secret_key=SecretKey,
            salt=Salt,
            sep=Sep}.

-spec ts_signer(binary(), age()) -> #signer{}.
ts_signer(SecretKey, MaxAge) ->
    ts_signer(SecretKey, MaxAge, ?DEFAULT_SALT_SIGNER, ?DEFAULT_SEP).

-spec ts_signer(binary(), age(), binary()) -> #signer{}.
ts_signer(SecretKey, MaxAge, Salt) ->
    ts_signer(SecretKey, MaxAge, Salt, ?DEFAULT_SEP).

-spec ts_signer(binary(), age(), binary(), binary()) -> #signer{}.
ts_signer(SecretKey, MaxAge, Salt, Sep)
  when is_binary(SecretKey) andalso
       is_binary(Salt) andalso
       is_binary(Sep) andalso
       (MaxAge == infinity orelse (is_integer(MaxAge) andalso
                                   MaxAge >= 0)) ->
    #signer{type={timed, MaxAge},
            secret_key=SecretKey,
            salt=Salt,
            sep=Sep}.

-spec get_signature(#signer{}, binary()) -> binary().
get_signature(Signer, Value) ->
    Key = ?SHA([Signer#signer.salt, <<"signer">>, Signer#signer.secret_key]),
    Mac = ?SHA_MAC(Key, Value),
    base64_encode(Mac).

-spec sign(#signer{}, binary()) -> binary().
sign(#signer{type=untimed}=Signer, Value) ->
    Signature = get_signature(Signer, Value),
    <<Value/binary, (Signer#signer.sep)/binary, Signature/binary>>;
sign(#signer{type={timed, _}}=Signer, Value) ->
    Sep = Signer#signer.sep,
    Ts = base64_encode(binary:encode_unsigned(etsd_now())),
    TimedValue = <<Value/binary, Sep/binary, Ts/binary>>,
    Signature = get_signature(Signer, TimedValue),
    <<TimedValue/binary, Sep/binary, Signature/binary>>.

-spec unsign(#signer{}, binary()) -> {ok, {binary(),
                                           calendar:datetime() | undefined}}
                                   | {error, bad_signature}
                                   | {error, timestamp_missing}
                                   | {error, signature_expired}.
unsign(#signer{type=untimed}=Signer, Bin) ->
    case unsign_untimed(Signer, Bin) of
        {ok, Val} -> {ok, {Val, undefined}};
        {error, _}=E -> E
    end;
unsign(#signer{type={timed, MaxAge}}=Signer, Bin) ->
    case unsign_untimed(Signer, Bin) of
        {ok, TimedVal} ->
            case split_tail(TimedVal, Signer#signer.sep) of
                {ok, {Val, Ts}} ->
                    EtsdTime = binary:decode_unsigned(base64_decode(Ts)),
                    Age = etsd_now() - EtsdTime,
                    case MaxAge of
                        infinity -> {ok, {Val, datetime_from_etsd(EtsdTime)}};
                        MaxAge when is_integer(MaxAge), Age =< MaxAge ->
                            {ok, {Val, datetime_from_etsd(EtsdTime)}};
                        MaxAge when is_integer(MaxAge) ->
                            {error, signature_expired}
                    end;
                {error, no_tail} ->
                    {error, timestamp_missing}
            end;
        {error, bad_signature}=E -> E
    end.

-spec validate(#signer{}, binary()) -> boolean().
validate(Signer, Bin) ->
    case unsign(Signer, Bin) of
        {ok, _Value}           -> true;
        {error, bad_signature} -> false
    end.

%%% Internal functions
-spec unsign_untimed(#signer{}, binary()) -> {ok, binary()}
                                           | {error, bad_signature}.
unsign_untimed(Signer, Bin) ->
    case split_tail(Bin, Signer#signer.sep) of
        {ok, {Value, Signature}} ->
            case get_signature(Signer, Value) of
                Signature -> {ok, Value};
                _         -> {error, bad_signature}
            end;
        {error, no_tail} -> {error, bad_signature}
    end.

-spec split_tail(binary(), binary()) -> {ok, {binary(), binary()}}
                                      | {error, no_tail}.
split_tail(Bin, Sep) ->
    case binary:matches(Bin, Sep) of
        [] -> {error, no_tail};
        Matches ->
            {SepPos, SepLen} = lists:last(Matches),
            <<Head:SepPos/binary, _Sep:SepLen/binary, Tail/binary>> = Bin,
            {ok, {Head, Tail}}
    end.

-spec base64_encode(binary()) -> binary().
base64_encode(Bin) when is_binary(Bin) ->
    Len = size(Bin),
    TrimmedLen = ((Len - 1) * 4 div 3) + 2,
    <<TrimmedB64:TrimmedLen/binary, _/binary>> = base64:encode(Bin),
    << <<(b64_to_urlsafe(B)):8>> || <<B:8/integer>> <= TrimmedB64 >>.

b64_to_urlsafe($+) -> $-;
b64_to_urlsafe($/) -> $_;
b64_to_urlsafe(C)  -> C.

base64_decode(Bin) when is_binary(Bin) ->
    %% Note(Sergei): crappy Erlang doesn't have a proper modulo operator.
    Padding = binary:part(<<"===">>, 0, 4 + (-size(Bin) rem 4)),
    PaddedB64 = <<Bin/binary, Padding/binary>>,
    base64:decode(<< <<(urlsafe_to_b64(B)):8>>
                     || <<B:8/integer>> <= PaddedB64>>).

urlsafe_to_b64($-) -> $+;
urlsafe_to_b64($_) -> $/;
urlsafe_to_b64(C)  -> C.

-spec etsd_now() -> pos_integer().
etsd_now() ->
    etsd_from_datetime(calendar:universal_time()).

-spec etsd_from_datetime(calendar:datetime()) -> pos_integer().
etsd_from_datetime(DT) ->
    {Ds, {H, M, S}} = calendar:time_difference(?EPOCH, DT),
    ((Ds * 24 + H) * 60 + M) * 60 + S.

-spec datetime_from_etsd(pos_integer()) -> calendar:datetime().
datetime_from_etsd(Etsd) ->
    Secs = Etsd + calendar:datetime_to_gregorian_seconds(?EPOCH),
    calendar:gregorian_seconds_to_datetime(Secs).
