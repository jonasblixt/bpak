#ifndef INCLUDE_BPAK_KEY_H
#define INCLUDE_BPAK_KEY_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \def BPAK_DECLARE_STATIC_KEY
 * Declare a 'struct bpak_key *' called '__name' with room for '__size' bytes
 * of key data on the stack
 */
#define BPAK_DECLARE_STATIC_KEY(__name, __size) \
    uint8_t __##__name##_data[sizeof(struct bpak_key) + __size]; \
    struct bpak_key *__name = (struct bpak_key *) __##__name##_data; \
    __name->size = __size;

/**
 * A key, followed by its DER encoded data
 */
struct bpak_key {
    enum bpak_key_kind kind; /*!< Kind of key */
    uint16_t size;           /*!< Size of 'data' in bytes */
    uint32_t id;             /*!< Key id, the part id in a keystore */
    uint8_t rz[4];           /*!< Reserved, set to zero */
    uint8_t data[];          /*!< DER encoded key */
};

#ifdef __cplusplus
} // extern "C"
#endif

#endif // INCLUDE_BPAK_KEY_H
