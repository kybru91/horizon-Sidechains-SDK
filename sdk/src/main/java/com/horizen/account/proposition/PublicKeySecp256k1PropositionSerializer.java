package com.horizen.account.proposition;

import com.horizen.account.utils.Secp256k1;
import com.horizen.proposition.PropositionSerializer;
import scorex.util.serialization.Reader;
import scorex.util.serialization.Writer;

public final class PublicKeySecp256k1PropositionSerializer
    implements PropositionSerializer<PublicKeySecp256k1Proposition> {
    private static final PublicKeySecp256k1PropositionSerializer serializer;

    static {
        serializer = new PublicKeySecp256k1PropositionSerializer();
    }

    private PublicKeySecp256k1PropositionSerializer() {
        super();
    }

    public static PublicKeySecp256k1PropositionSerializer getSerializer() {
        return serializer;
    }

    @Override
    public void serialize(PublicKeySecp256k1Proposition proposition, Writer writer) {
        writer.putBytes(proposition.pubKeyBytes());
    }

    @Override
    public PublicKeySecp256k1Proposition parse(Reader reader) {
        byte[] publicKey = reader.getBytes(Secp256k1.PUBLIC_KEY_SIZE);
        return new PublicKeySecp256k1Proposition(publicKey);
    }
}