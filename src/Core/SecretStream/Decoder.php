<?php
declare(strict_types=1);

/**
 * Class ParagonIE_Sodium_Core_SecretStream_Decoder
 *
 * Bounded decoder for crypto_secretstream_xchacha20poly1305.
 *
 * The low-level pull primitive hands TAG_FINAL back to the caller and keeps
 * advancing its state, so a caller that forgets to stop will keep decoding
 * post-final frames as if they were part of the stream. This wrapper enforces
 * the stream boundary instead:
 *
 * - Empty / truncated frames are rejected before touching any state.
 * - Frames after TAG_FINAL are rejected.
 * - Tags with bits outside TAG_MESSAGE|TAG_PUSH|TAG_REKEY|TAG_FINAL are rejected.
 * - On authentication failure the pull state is rolled back, so the decoder
 *   can still decode the (untampered) frame afterwards.
 */
class ParagonIE_Sodium_Core_SecretStream_Decoder
{
    /** @var string */
    protected string $state;

    /** @var bool */
    protected bool $finalized = false;

    /**
     * @param string $state Pull state from crypto_secretstream_xchacha20poly1305_init_pull()
     */
    public function __construct(
        #[SensitiveParameter]
        string $state
    ) {
        $this->state = $state;
    }

    /**
     * Initialize a decoder from a stream header and key.
     *
     * @param string $header
     * @param string $key
     * @return self
     * @throws SodiumException
     */
    public static function fromHeaderAndKey(
        string $header,
        #[SensitiveParameter]
        string $key
    ): self {
        return new self(
            ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_pull($header, $key)
        );
    }

    /**
     * Has a TAG_FINAL frame been decoded?
     *
     * @return bool
     */
    public function isFinalized(): bool
    {
        return $this->finalized;
    }

    /**
     * Decode one frame of the stream.
     *
     * @param string $ciphertext
     * @param string $aad
     * @return array{0: string, 1: int} plaintext and tag
     * @throws SodiumException On empty/truncated input, post-final frames,
     *                         invalid tags, or authentication failure.
     */
    public function pull(
        string $ciphertext,
        string $aad = ''
    ): array {
        if ($this->finalized) {
            throw new SodiumException(
                'secretstream is finalized (TAG_FINAL received); no further frames may be decoded'
            );
        }
        if (ParagonIE_Sodium_Core_Util::strlen($ciphertext) <
            ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES) {
            throw new SodiumException(
                'secretstream frame must be at least SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES bytes'
            );
        }

        // Operate on a copy; only commit to the real state on success.
        $working = $this->state;
        $result = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_pull(
            $working,
            $ciphertext,
            $aad
        );
        if ($result === false) {
            // Authentication failed: roll back (do not commit $working).
            throw new SodiumException('secretstream authentication failure');
        }
        /** @var array{0: string, 1: int} $result */
        list($plaintext, $tag) = $result;
        if (($tag & ~0x03) !== 0) {
            // Unknown tag bits set: reject without committing state.
            throw new SodiumException('secretstream frame carries an invalid tag');
        }

        $this->state = $working;
        if ($tag === ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
            $this->finalized = true;
        }
        return array($plaintext, $tag);
    }
}
