# etsdangerous

__Authors:__ [Dmitry Groshev] (https://github.com/si14/), [Sergei Lebedev] (https://github.com/superbobry/).

An Erlang port of [itsangerous](https://github.com/mitsuhiko/itsdangerous).

Quick examples
--------------

#### Signing:

```erlang
1> S = etsdangerous:signer(<<"secret-key>>>).
{signer,untimed,<<"secret-key">>,<<"etsdangerous.Signer">>,
        <<".">>}
2> D = etsdangerous:sign(S, <<"data">>).
<<"data.tfT7zMsPOFv84VxV6CUew_09xvs">>
3> etsdangerous:unsign(S, D).
{ok,{<<"data">>,undefined}}
```

#### Exparing signatures:

```erlang
1> S = etsdangerous:ts_signer(<<"secret-key">>, 10).
{signer,{timed,10},
        <<"secret-key">>,<<"etsdangerous.Signer">>,<<".">>}
2> D = etsdangerous:sign(S, <<"data">>).
<<"data.BCyr0A.qmWS3-TkJ9eiElgZELGmubxsuRA">>
3> etsdangerous:unsign(S, D).
{ok,{<<"data">>,{{2013,3,21},{14,33,52}}}}
...
4> etsdangerous:unsign(S, D).
{error,signature_expired}
```

#### Salt:

```erlang
1> S1 = etsdangerous:signer(<<"secret-key">>, <<"salt-1">>).
{signer,untimed,<<"secret-key">>,<<"salt-1">>,<<".">>}
2> S2 = etsdangerous:signer(<<"secret-key">>, <<"salt-2">>).
{signer,untimed,<<"secret-key">>,<<"salt-2">>,<<".">>}
3> D = etsdangerous:sign(S1, <<"data">>).
<<"data.siZlJhySx8NoTIwrmOmupfvGnO8">>
4> etsdangerous:unsign(S2, D).
{error,bad_signature}
```
