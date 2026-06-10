package com.demo.upimesh.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.demo.upimesh.model.PaymentInstruction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

/**
 * Hybrid encryption — the same pattern used by TLS, PGP, Signal, etc.
 *
 * Why hybrid? RSA can only encrypt small data (~245 bytes for a 2048-bit key).
 * Our payment instruction (JSON) might be ~300 bytes, and in real use we might
 * include device certificates and signatures pushing it well over.
 *
 * Solution: generate a fresh AES key per packet, encrypt the JSON with AES-GCM
 * (fast + authenticated), then encrypt JUST the AES key with RSA-OAEP.
 *
 * Wire format (after base64 encoding):
 *   [ 256 bytes RSA-encrypted AES key ][ 12 bytes GCM IV ][ ciphertext + 16-byte tag ]
 *
 * AES-GCM is authenticated encryption: any single-bit tampering with the ciphertext
 * causes decryption to fail with an exception. This is what makes it safe for
 * untrusted intermediates to hold.
 */


@Service
public class HybridCryptoService {

    private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int RSA_ENCRYPTED_KEY_BYTES = 256; // for 2048-bit RSA

    private final SecureRandom rng = new SecureRandom();
    private final ObjectMapper json = new ObjectMapper();

    @Autowired
    private ServerKeyHolder serverKey;

    /**
     * Encrypt a payment instruction with the server's public key.
     * Called by the simulated sender device.
     *
     * Step 1 : Serialize : byte[]
     * Step 2: AES generation (SecretKey per packet): (32bytes)
     * Step3 : Plaintext->cipher+tag : 12byte  IV generated  + 16-byte GCM auth tag
     * Step 4 : AES key->256 encrypted bytes : 256 bytes
     * Step5 : [256B AES + 12B IV + Cipher+ 16B Tag] -> Base64 string
     */

    public String encrypt(PaymentInstruction instruction, PublicKey serverPublicKey) throws Exception {

        // PaymentInstruction object → raw bytes (JSON)
        byte[] plaintext = json.writeValueAsBytes(instruction);

        // 1. Generate a one-time AES key for this packet.
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_BITS);
        SecretKey aesKey = kg.generateKey();
// This key is thrown away after encryption — never stored, never reused


        // 2. AES-GCM encrypt the payload.
        byte[] iv = new byte[GCM_IV_BYTES];
        rng.nextBytes(iv);
        Cipher aes = Cipher.getInstance(AES_TRANSFORMATION);
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] aesCiphertext = aes.doFinal(plaintext);

        // 3. RSA-OAEP encrypt the AES key with the server's public key.
        Cipher rsa = Cipher.getInstance(RSA_TRANSFORMATION);
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        rsa.init(Cipher.ENCRYPT_MODE, serverPublicKey, oaep);
        byte[] encryptedAesKey = rsa.doFinal(aesKey.getEncoded());

        // 4. Pack: [encrypted AES key][IV][AES ciphertext + tag]
        ByteBuffer buf = ByteBuffer.allocate(encryptedAesKey.length + iv.length + aesCiphertext.length);
        buf.put(encryptedAesKey);
        buf.put(iv);
        buf.put(aesCiphertext);

        return Base64.getEncoder().encodeToString(buf.array());
    }

    /**
     * Decrypt with the server's private key.
     * If anything has been tampered with — wrong key, modified ciphertext,
     * truncated input — this throws.
     *
     *
     * Step 1: Base64 decode — Base64 string → raw byte[] [256B + 12B + cipher + 16B]
     * Step 2: Length guard — throw if length < 284 bytes (256 + 12 + 16 minimum)
     * Step 3: ByteBuffer unpack — slice → encryptedAesKey[256B] + IV[12B] + aesCiphertext
     * Step 4: RSA-OAEP unwrap — 256B encrypted key → 32B AES key (server private key only)
     * Step 5: AES-GCM decrypt + verify — cipher+tag → plaintext (throws AEADBadTagException if tampered)
     * Step 6: JSON deserialize — byte[] → PaymentInstruction (sender, receiver, amount, nonce, signedAt)
     *
     */
    public PaymentInstruction decrypt(String base64Ciphertext) throws Exception {
        byte[] all = Base64.getDecoder().decode(base64Ciphertext);

        // contain the minimum structure (256 RSA + 12 IV + 16 GCM tag)?
        if (all.length < RSA_ENCRYPTED_KEY_BYTES + GCM_IV_BYTES + GCM_TAG_BITS / 8) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        // Unpack
        byte[] encryptedAesKey = new byte[RSA_ENCRYPTED_KEY_BYTES];  // first 256 bytes
        byte[] iv = new byte[GCM_IV_BYTES];  // next 12 bytes
        byte[] aesCiphertext = new byte[all.length - RSA_ENCRYPTED_KEY_BYTES - GCM_IV_BYTES];

        ByteBuffer buf = ByteBuffer.wrap(all);
        buf.get(encryptedAesKey);
        buf.get(iv);
        buf.get(aesCiphertext);

        // Step 1: Server uses its PRIVATE key to unwrap the AES key
        Cipher rsa = Cipher.getInstance(RSA_TRANSFORMATION);
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        rsa.init(Cipher.DECRYPT_MODE, serverKey.getPrivateKey(), oaep);
        byte[] aesKeyBytes = rsa.doFinal(encryptedAesKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // 2. AES-GCM decrypt + verify the tag.
        // If any byte of aesCiphertext was modified, doFinal() throws AEADBadTagException
        // This is the tamper detection — no explicit check needed, GCM handles it
        Cipher aes = Cipher.getInstance(AES_TRANSFORMATION);
        aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] plaintext = aes.doFinal(aesCiphertext);

        return json.readValue(plaintext, PaymentInstruction.class);
    }

    /**
     * SHA-256 of the ciphertext. THIS is the idempotency key.
     *
     * Why ciphertext and not packetId? Because intermediates can rewrite packetId
     * but cannot forge a valid ciphertext for a different payload. Two delivered
     * copies of the same packet have identical ciphertexts, hence identical hashes.
     */
    public String hashCiphertext(String base64Ciphertext) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(base64Ciphertext.getBytes());

        // Convert raw bytes to lowercase hex string (64 chars for SHA-256)
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
