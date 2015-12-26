-module(eece).

-export([encrypt/3
        ,encrypt/4
        ,extract_key/2
        ,decrypt/3
        ,decrypt/4
        ]).

-export([urlsafe_decode64/1
        ,urlsafe_encode64/1
        ]).

-define(AEAD_CIPHER, aes_gcm).
-define(HASH_ALGO, sha256).
-define(KEY_LENGTH, 16).
-define(TAG_LENGTH, 16).
-define(NONCE_LENGTH, 12).
-define(RS, 4096).


-spec(encrypt(binary(), binary(), binary()) -> binary()).
encrypt(Data, IKM, Salt) ->
    encrypt(Data, IKM, Salt, ?RS).

-spec(encrypt(binary(), binary(), binary(), pos_integer()) -> binary()).
encrypt(Data, IKM, Salt, RS) when RS > 0 ->
    {ok, Key, Nonce} = extract_key(IKM, Salt),
    encrypt_blocks(Data, Key, Nonce, RS-1).

-spec(extract_key(binary(), binary()) -> {ok, binary(), binary()} ).
extract_key(IKM, Salt) ->
    Key   = hkdf:derive_secrets(?HASH_ALGO, IKM, <<"Content-Encoding: aesgcm128">>, Salt, ?KEY_LENGTH),
    Nonce = hkdf:derive_secrets(?HASH_ALGO, IKM, <<"Content-Encoding: nonce">>, Salt, ?NONCE_LENGTH),
    {ok, Key, Nonce}.

-spec(decrypt(binary(), binary(), binary()) -> binary()).
decrypt(Data, IKM, Salt) ->
    decrypt(Data, IKM, Salt, ?RS).

-spec(decrypt(binary(), binary(), binary(), pos_integer()) -> binary()).
decrypt(Data, IKM, Salt, RS) when RS >= 2, byte_size(Data) rem RS =/= 0 ->
    {ok, Key, Nonce} = extract_key(IKM, Salt),
    decrypt_blocks(Data, Key, Nonce, RS+16).


%% ============================================================
%% internal funcs
%% ============================================================

%% decrypt
decrypt_blocks(Bin, Key, Nonce, RS) ->
    decrypt_blocks(Bin, Key, Nonce, RS, 0, []).

decrypt_blocks(Bin, Key, Nonce, Len, Ctr, Acc) when byte_size(Bin) =< Len ->
    {ok, Text} = decrypt_block(Bin, Key, Nonce, Ctr),
    list_to_binary(lists:reverse([Text | Acc]));
decrypt_blocks(Bin, Key, Nonce, Len, Ctr, Acc) ->
    {ok, Text} = decrypt_block(Bin, Key, Nonce, Ctr),
    decrypt_blocks(Bin, Key, Nonce, Len, Ctr+1, [Text | Acc]).

decrypt_block(Bin, Key, Nonce, Ctr) ->
    Len = byte_size(Bin) -?TAG_LENGTH,
    <<CText:Len/big-unit:8, Tag/binary>> = Bin,
    CBin = <<CText:Len/unit:8>>,
    IVec = generate_ivec(Nonce, Ctr),
    <<0,Text/binary>> = crypto:block_decrypt(?AEAD_CIPHER, Key, IVec, {<<>>, CBin, Tag}),
    {ok, Text}.

%% encrypt
-spec(encrypt_blocks(binary(), binary(), binary(), pos_integer()) -> binary()).
encrypt_blocks(Bin, Key, Nonce, RS) ->
    encrypt_blocks(Bin, Key, Nonce, RS, 0, []).

encrypt_blocks(Bin, Key, Nonce, Len, Ctr, Acc) when byte_size(Bin) =< Len ->
    {ok, CText} = encrypt_block(Bin, Key, Nonce, Ctr),
    erlang:list_to_binary(lists:reverse([CText | Acc]));
encrypt_blocks(Bin, Key, Nonce, Len, Ctr, Acc) ->
    <<Part:Len, Rest/binary>> = Bin,
    {ok, CText} = encrypt_block(Part, Key, Nonce, Ctr),
    encrypt_blocks(Rest, Key, Nonce, Len, Ctr+1, [CText | Acc]).

encrypt_block(Bin, Key, Nonce, Ctr) ->
    IVec = generate_ivec(Nonce, Ctr),
    {CText, CTag} = crypto:block_encrypt(?AEAD_CIPHER, Key, IVec, {<<>>, <<0,Bin/binary>>}),
    {ok, <<CText/binary, CTag/binary>>}.

%%
generate_ivec(Nonce, Ctr) ->
    <<H:4/unit:8, Mask/binary>> = Nonce,
    <<IMask:8/integer-unit:8>> = Mask,
    Next = Ctr bxor IMask,
    <<H:4/unit:8, Next:8/integer-unsigned-big-unit:8>>.




urlsafe_decode64(Str) ->
    Str2 = re:replace(Str, "-", "+", [global, {return,list}]),
    Str3 = re:replace(Str2, "_", "/", [global, {return,list}]),
    base64:decode(Str3).

urlsafe_encode64(Bin) ->
    Bin2 = base64:encode(Bin),
    Bin3 = re:replace(binary_to_list(Bin2), "\\+", "-", [global, {return,list}]),
    re:replace(Bin3, "/", "_", [global, {return,list}]).


-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").
-define(MSG, <<"This is a test for content encryption encoding.">>).

%% testing
eece_test() ->
    Salt = urlsafe_decode64("mUFsKgrmI-i_-HowjX_2XA=="),
    Key  = urlsafe_decode64("F-hAEGCm7KIGUiSdS4GGtA=="),
    Msg  = urlsafe_decode64("iEPbDBuohQLznv45IlaF1eLRCeu6aWfsq-pDP7OnzgH4A0x5lyIEVAfM39RgeLekW1VgZWIFL_WvuveEhaHj0-iEvxDHw_apYGFYWEY6KmMhXgWPmFZ-2wAMnDsQ-DDVbZHsXw=="),
    E = encrypt(Msg, Key, Salt),
    io:format("Enc msg:~p~n", [E]),
    D = decrypt(E, Key, Salt),
    D = Msg.

http_req_test() ->
    Type = ecdh,
    Curve = prime256v1,
    {PubKey1, _PrivKey1} = crypto:generate_key(Type, Curve),
    {_PubKey2, PrivKey2} = crypto:generate_key(Type, Curve),
    SharedSecret = crypto:compute_key(Type, PubKey1, PrivKey2, Curve),
    Salt = crypto:rand_bytes(16),
    E = encrypt(?MSG, SharedSecret, Salt),
    D = decrypt(E, SharedSecret, Salt),
    D = ?MSG.

-endif.
