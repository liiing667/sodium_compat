<?php
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Class SecretStreamTest
 */
#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SecretStreamTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testStateSerialization(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        $nonce = random_bytes(12);
        $state = new ParagonIE_Sodium_Core_SecretStream_State($key, $nonce);
        $toString = $state->toString();
        $fromString = ParagonIE_Sodium_Core_SecretStream_State::fromString($toString);

        $this->assertSame(
            $state->getNonce(),
            $fromString->getNonce()
        );
        $this->assertSame(
            $state->getCounter(),
            $fromString->getCounter()
        );
        $this->assertSame(
            $state->getKey(),
            $fromString->getKey()
        );
    }

    /**
     * @throws Exception
     */
    public function testSecretStreamMain(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        list($pushState, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $pullState = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        $this->assertEquals(bin2hex($pushState), bin2hex($pullState));

        $aad = '';
        for ($i = 0; $i < 20; ++$i) {
            $msg = random_bytes(1024);
            if ($i === 10) {
                $aad = 'test';
            }
            $encrypt = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($pushState, $msg, $aad);
            list($decrypt, $tag) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_pull($pullState, $encrypt, $aad);
            $this->assertEquals(bin2hex($pushState), bin2hex($pullState));
            $this->assertEquals(bin2hex($msg), bin2hex($decrypt));
            $this->assertEquals(0, $tag);
        }
        ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_rekey($pushState);
        ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_rekey($pullState);
        $this->assertEquals(bin2hex($pushState), bin2hex($pullState));
    }

    /**
     * Known-answer vector for the bounded decoder, cross-checked against
     * native libsodium (ext-sodium pulls these exact ciphertexts).
     *
     * @throws Exception
     */
    public function testDecoderMatchesNativeVectors(): void
    {
        $key = str_repeat("\x01", 32);
        $header = str_repeat("\x02", 24);
        $frames = array(
            // [ciphertext hex, aad, expected plaintext, expected tag]
            array(
                '92ebbb173073add65a3cf4d48ff2203e8802235e1c43b46cc1d84bf4',
                '',
                'hello world',
                ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH
            ),
            array(
                'c9888b48c0d242f1f3c9a3924eb2764819267c4fe9b03727f5c38e2cf6',
                'aad',
                'second frame',
                ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PULL
            ),
            array(
                '1ca32ef93375dcdc70ec2203ed0c00fff8ec81364ae83e8e11',
                '',
                'rekey me',
                ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY
            ),
            array(
                'c7b90d4a89e98670eb71f015e56e4b0a24',
                '',
                '',
                ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
            ),
        );

        $decoder = ParagonIE_Sodium_Core_SecretStream_Decoder::fromHeaderAndKey($header, $key);
        $this->assertFalse($decoder->isFinalized());
        foreach ($frames as $frame) {
            list($plaintext, $tag) = $decoder->pull(hex2bin($frame[0]), $frame[1]);
            $this->assertSame($frame[2], $plaintext);
            $this->assertSame($frame[3], $tag);
        }
        $this->assertTrue($decoder->isFinalized());
    }

    /**
     * Cross-check a random stream against native libsodium in both directions.
     *
     * @throws Exception
     */
    public function testDecoderInteropWithNativeLibsodium(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium not loaded');
        }
        $key = random_bytes(32);

        // Native push -> bounded decoder pull
        list($nativePush, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        $decoder = ParagonIE_Sodium_Core_SecretStream_Decoder::fromHeaderAndKey($header, $key);
        for ($i = 0; $i < 10; ++$i) {
            $msg = random_bytes(mt_rand(0, 256));
            $aad = ($i % 2 === 0) ? 'aad-' . $i : '';
            $tag = ($i === 9) ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : ($i % 3);
            $cipher = sodium_crypto_secretstream_xchacha20poly1305_push($nativePush, $msg, $aad, $tag);
            list($plaintext, $outTag) = $decoder->pull($cipher, $aad);
            $this->assertSame($msg, $plaintext);
            $this->assertSame($tag, $outTag);
        }
        $this->assertTrue($decoder->isFinalized());

        // Compat push -> native pull
        list($pushState, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $nativePull = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        for ($i = 0; $i < 10; ++$i) {
            $msg = random_bytes(mt_rand(0, 256));
            $aad = ($i % 2 === 0) ? 'aad-' . $i : '';
            $tag = ($i === 9)
                ? ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                : ($i % 3);
            $cipher = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($pushState, $msg, $aad, $tag);
            list($plaintext, $outTag) = sodium_crypto_secretstream_xchacha20poly1305_pull($nativePull, $cipher, $aad);
            $this->assertSame($msg, $plaintext);
            $this->assertSame($tag, $outTag);
        }
    }

    /**
     * @throws Exception
     */
    public function testDecoderRejectsEmptyStream(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        list(, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $decoder = ParagonIE_Sodium_Core_SecretStream_Decoder::fromHeaderAndKey($header, $key);

        try {
            $decoder->pull('');
            $this->fail('Expected SodiumException for empty ciphertext');
        } catch (SodiumException $ex) {
            $this->assertStringContainsString('ABYTES', $ex->getMessage());
        }

        // Truncated frame (shorter than ABYTES) must also be rejected:
        try {
            $decoder->pull(random_bytes(16));
            $this->fail('Expected SodiumException for truncated ciphertext');
        } catch (SodiumException $ex) {
            $this->assertStringContainsString('ABYTES', $ex->getMessage());
        }
    }

    /**
     * @throws Exception
     */
    public function testDecoderRejectsFramesAfterFinal(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        list($pushState, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $decoder = ParagonIE_Sodium_Core_SecretStream_Decoder::fromHeaderAndKey($header, $key);

        $final = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push(
            $pushState,
            'last',
            '',
            ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
        );
        list($plaintext, $tag) = $decoder->pull($final);
        $this->assertSame('last', $plaintext);
        $this->assertSame(
            ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
            $tag
        );
        $this->assertTrue($decoder->isFinalized());

        // The pusher keeps going; the decoder must not:
        $extra = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($pushState, 'extra');
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('finalized');
        $decoder->pull($extra);
    }

    /**
     * @throws Exception
     */
    public function testDecoderRejectsInvalidTag(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        list($pushState, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $decoder = ParagonIE_Sodium_Core_SecretStream_Decoder::fromHeaderAndKey($header, $key);

        // Push a frame whose tag byte carries bits outside the valid 0..3 range:
        $cipher = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push(
            $pushState,
            'bogus tag',
            '',
            0x80
        );
        try {
            $decoder->pull($cipher);
            $this->fail('Expected SodiumException for invalid tag');
        } catch (SodiumException $ex) {
            $this->assertStringContainsString('invalid tag', $ex->getMessage());
        }

        // State must have been rolled back, not committed:
        $this->assertFalse($decoder->isFinalized());
    }

    /**
     * @throws Exception
     */
    public function testDecoderRollsBackStateOnAuthFailure(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        list($pushState, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $decoder = ParagonIE_Sodium_Core_SecretStream_Decoder::fromHeaderAndKey($header, $key);

        $msg = 'authenticated message';
        $cipher = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($pushState, $msg);

        // Tamper with the ciphertext: authentication must fail.
        $tampered = $cipher;
        $tampered[5] = \chr(\ord($tampered[5]) ^ 0x01);
        try {
            $decoder->pull($tampered);
            $this->fail('Expected SodiumException for authentication failure');
        } catch (SodiumException $ex) {
            $this->assertStringContainsString('authentication', $ex->getMessage());
        }

        // Wrong AAD must also fail:
        try {
            $decoder->pull($cipher, 'wrong aad');
            $this->fail('Expected SodiumException for authentication failure');
        } catch (SodiumException $ex) {
            $this->assertStringContainsString('authentication', $ex->getMessage());
        }

        // State was rolled back: the untampered frame still decodes correctly.
        list($plaintext, $tag) = $decoder->pull($cipher);
        $this->assertSame($msg, $plaintext);
        $this->assertSame(
            ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH,
            $tag
        );

        // And the stream stays in sync for subsequent frames:
        $msg2 = 'next frame';
        $cipher2 = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push(
            $pushState,
            $msg2,
            '',
            ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
        );
        list($plaintext2, $tag2) = $decoder->pull($cipher2);
        $this->assertSame($msg2, $plaintext2);
        $this->assertSame(
            ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
            $tag2
        );
        $this->assertTrue($decoder->isFinalized());
    }
}
