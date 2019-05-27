/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "utils.h"
#include "menu.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include "simple.pb.h"
#include "init.pb.h"
#include "psd.pb.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#define CLA 0xE0
#define INS_GET_APP_CONFIGURATION 0x01
#define INS_ENCODE 0x02
#define INS_DECODE 0x03

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5


#define MAX_BIP32_PATH_SIZE 10
uint8_t buffer[512];
uint8_t message_length;
uint8_t bip32_path_size;
uint32_t bip32_path[MAX_BIP32_PATH_SIZE];

uint8_t *parse_bip32arg(uint8_t *src, uint8_t *bip32NbElem, uint32_t *bip32Path, size_t maxNbElem)
{
    int i;
    *bip32NbElem = src[0];

    if (*bip32NbElem > maxNbElem)
    {
        THROW(0x6B90);
    }

    for (i = 0; i < *bip32NbElem; i++)
    {
        bip32Path[i] = U4BE(src + 1, i * 4);
    }

    return src + 1 + i * 4;
}

uint8_t *vault_operation_prefix_parser(uint8_t *apdu_buffer, const uint8_t maxLen, uint8_t* first_chunk_size, uint16_t* total_message_size)
{
    //validate_vault_operation_context_t *op = &acquireContext(OPERATION)->u.operation;

    bip32_path_size = 0;
    os_memset(bip32_path, 0, MAX_BIP32_PATH_SIZE);

    uint8_t* buffer = parse_bip32arg(apdu_buffer+OFFSET_CDATA, &bip32_path_size, bip32_path, MAX_BIP32_PATH_SIZE);

    PRINTF("path: %.*H\n", bip32_path_size*4, bip32_path);

    uint16_t prefixLen = buffer - (G_io_apdu_buffer + OFFSET_CDATA);

    // sanity check, if prefix_parser returned an error
    // or parsed too long => SW_WRONG_LENGTH
    if (buffer == NULL || prefixLen > G_io_apdu_buffer[OFFSET_LC])
    {
        THROW(0x6700);
    }

    // LC on first APDU has to at least be 2 + parsed prefix length
    if(G_io_apdu_buffer[OFFSET_LC] < 2 + prefixLen){
        THROW(0x6700);
    }

    *total_message_size = buffer[0] << 8 | buffer[1];
    buffer += 2;

    PRINTF("total pb message size: %d\n", *total_message_size);

    *first_chunk_size = maxLen - ((buffer - apdu_buffer) - OFFSET_CDATA); // TODO: à vérifier

    return buffer;
}
 
void handleApdu(volatile unsigned int *flags, volatile unsigned int *tx) {
    unsigned short sw = 0;

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
            THROW(0x6E00);
            }

            // reset memory allocation context
            os_memset(&G_malloc_ctx, 0, sizeof(G_malloc_ctx));

            switch (G_io_apdu_buffer[OFFSET_INS]) {

                case 0x0A:
                {
                    uint8_t status;
                    uint8_t first_chunk_size;
                    uint16_t total_message_size;

                    ledgervault_psd_PsdRequest psd_request = ledgervault_psd_PsdRequest_init_zero;

                    if(G_io_apdu_buffer[OFFSET_P1] != P1_FIRST){
                        THROW(ERR_WRONG_PARAMETER);
                    }

                    uint8_t* buffer = vault_operation_prefix_parser(G_io_apdu_buffer, G_io_apdu_buffer[OFFSET_LC], &first_chunk_size, &total_message_size);

                    pb_istream_t stream = pb_istream_from_wrapped_apdu(buffer, first_chunk_size, total_message_size);

                    status = pb_decode(&stream, ledgervault_psd_PsdRequest_fields, &psd_request);

                    if (!status)
                    {
                        PRINTF("Decoding failed: %s\n", PB_GET_ERROR(&stream));
                        THROW(0x6D00);
                    }
                    
                    /* Print the data contained in the message. */
                    PRINTF("Your lucky number was %.*H!\n", 32, psd_request.challenge);
                    PRINTF("Your lucky number was %.*H!\n", 65, psd_request.User->confidentialityKey);
                    PRINTF("Your lucky number was %s!\n", psd_request.User->name);


                    THROW(0x9000);
                    break;
                }

                case 0x0B:
                {
                    uint8_t key_buff[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

                    cx_aes_key_t key;

                    PRINTF("file: main.c - Line #154\n");

                    cx_aes_init_key(key_buff, 16, &key);

                    PRINTF("file: main.c - Line #156\n");

                    uint8_t buffer_l[128] = {0x0a, 0x20, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0xdd, 0x22, 0x4f, 0x08, 0x01, 0x10, 0x02, 0x1a, 0x06, 0x5a, 0x4f, 0x42, 0x4d, 0x41, 0x4e, 0x2a, 0x41, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                    uint8_t out_buffer[128] = {0};
                    
                    cx_aes(&key,
                            CX_LAST | CX_ENCRYPT | CX_CHAIN_CBC,
                            buffer_l,
                            128,
                            out_buffer,
                            128
                            );

                    PRINTF("%.*H\n", 128, out_buffer);

                    break;
                }

                 case INS_GET_APP_CONFIGURATION:
                    G_io_apdu_buffer[0] = (N_storage.dummy_setting_1 ? 0x01 : 0x00);
                    G_io_apdu_buffer[1] = (N_storage.dummy_setting_2 ? 0x01 : 0x00);
                    G_io_apdu_buffer[2] = LEDGER_MAJOR_VERSION;
                    G_io_apdu_buffer[3] = LEDGER_MINOR_VERSION;
                    G_io_apdu_buffer[4] = LEDGER_PATCH_VERSION;
                    *tx = 4;
                    THROW(0x9000);
                    break;


                case INS_DECODE:
                {
                    uint8_t status;

                    uint8_t buffer_l[115] = {0x0a, 0x20, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0xdd, 0x22, 0x4f, 0x08, 0x01, 0x10, 0x02, 0x1a, 0x06, 0x5a, 0x4f, 0x42, 0x4d, 0x41, 0x4e, 0x2a, 0x41, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04};
                    
                    ledgervault_psd_PsdRequest psd_request = ledgervault_psd_PsdRequest_init_zero;
                    
                    /* Create a stream that will write to our buffer. */
                    pb_istream_t stream = pb_istream_from_buffer(buffer_l, sizeof(buffer_l));

                    /* Now we are ready to decode the message. */
                    status = pb_decode(&stream, ledgervault_psd_PsdRequest_fields, &psd_request);
                    /* Check for errors... */
                    if (!status)
                    {
                        PRINTF("Decoding failed: %s\n", PB_GET_ERROR(&stream));
                        THROW(0x6D00);
                    }
                    
                    /* Print the data contained in the message. */
                    PRINTF("Your lucky number was %.*H!\n", 32, psd_request.challenge);
                    PRINTF("Your lucky number was %.*H!\n", 65, psd_request.User->confidentialityKey);
                    PRINTF("Your lucky number was %s!\n", psd_request.User->name);

                    THROW(0x9000);
                    break;
                }


                case INS_ENCODE:
                {
                    uint8_t status;

                    ledgervault_WrapFragment wrap_fragment = ledgervault_WrapFragment_init_zero;
                    
                    /* Create a stream that will write to our buffer. */
                    pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
                    
                    wrap_fragment.wrapBlob.size = 6;
                    os_memcpy(wrap_fragment.wrapBlob.bytes, "looool", 6);
                    uint8_t buffer_l[32] = {0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0xdd};
                    os_memcpy(wrap_fragment.ephemeralPublicKey, buffer_l, 32);

                    /* Now we are ready to encode the message! */
                    status = pb_encode(&stream, ledgervault_WrapFragment_fields, &wrap_fragment);
                    message_length = stream.bytes_written;
                    
                    PRINTF("Encoded:\n%.*H\n", sizeof(buffer), buffer);
                            
                    /* Then just check for any errors.. */
                    if (!status)
                    {
                        PRINTF("Encoding failed: %s\n", PB_GET_ERROR(&stream));
                        THROW(0x6D00);
                    }
                    
                    THROW(0x9000);
                    break;
                }
                

                default:
                    THROW(0x6D00);
                    break;
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e) {
        switch (e & 0xF000) {
            case 0x6000:
                sw = e;
                break;
            case 0x9000:
                // All is well
                sw = e;
                break;
            default:
                // Internal error
                sw = 0x6800 | (e & 0x7FF);
                break;
            }
            // Unexpected exception => report
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY {
        }
    }
    END_TRY;
}

void app_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                PRINTF("New APDU received:\n%.*H\n", rx, G_io_apdu_buffer);

                handleApdu(&flags, &tx);
            }
            CATCH(EXCEPTION_IO_RESET) {
              THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                    case 0x6000:
                        sw = e;
                        break;
                    case 0x9000:
                        // All is well
                        sw = e;
                        break;
                    default:
                        // Internal error
                        sw = 0x6800 | (e & 0x7FF);
                        break;
                }
                if (e != 0x9000) {
                    flags &= ~IO_ASYNCH_REPLY;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

//return_to_dashboard:
    return;
}

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t*)element);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
        case SEPROXYHAL_TAG_FINGER_EVENT:
            UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
            break;

        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
            break;

        case SEPROXYHAL_TAG_STATUS_EVENT:
            if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID && !(U4BE(G_io_seproxyhal_spi_buffer, 3) & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
                THROW(EXCEPTION_IO_RESET);
            }
            // no break is intentional
        default:
            UX_DEFAULT_EVENT();
            break;

        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
            UX_DISPLAYED_EVENT({});
            break;

        case SEPROXYHAL_TAG_TICKER_EVENT:
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer,
            {
            #ifndef TARGET_NANOX
                if (UX_ALLOWED) {
                    if (ux_step_count) {
                    // prepare next screen
                    ux_step = (ux_step+1)%ux_step_count;
                    // redisplay screen
                    UX_REDISPLAY();
                    }
                }
            #endif // TARGET_NANOX
            });
            break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}


unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
        case CHANNEL_KEYBOARD:
            break;

        // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
        case CHANNEL_SPI:
            if (tx_len) {
                io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

                if (channel & IO_RESET_AFTER_REPLIED) {
                    reset();
                }
                return 0; // nothing received from the master so far (it's a tx
                        // transaction)
            } else {
                return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                            sizeof(G_io_apdu_buffer), 0);
            }

        default:
            THROW(INVALID_PARAMETER);
    }
    return 0;
}


void app_exit(void) {

    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {

        }
    }
    END_TRY_L(exit);
}

void nv_app_state_init(){
    if (N_storage.initialized != 0x01) {
        internalStorage_t storage;
        storage.dummy_setting_1 = 0x00;
        storage.dummy_setting_2 = 0x00;
        storage.initialized = 0x01;
        nvm_write(&N_storage, (void*)&storage, sizeof(internalStorage_t));
    }
    dummy_setting_1 = N_storage.dummy_setting_1;
    dummy_setting_2 = N_storage.dummy_setting_2;
}

__attribute__((section(".boot"))) int main(int arg0) {
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    for (;;) {
        UX_INIT();

        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

                nv_app_state_init();

                os_memset(&G_malloc_ctx, 0, sizeof(G_malloc_ctx));

                USB_power(0);
                USB_power(1);

                ui_idle();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif // HAVE_BLE

                app_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX before continuing
                continue;
            }
            CATCH_ALL {
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();
    return 0;
}
