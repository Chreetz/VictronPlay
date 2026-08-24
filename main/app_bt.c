/*
 * BLE Combined Advertising and Scanning Example.
 *
 * SPDX-FileCopyrightText: 2021-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_bt.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "freertos/queue.h"
#include "bt_hci_common.h"

//#include "mbedtls/aes.h"
#include "psa/crypto.h"

// #include <mbedtls/aes.h>

//#include "mbedtls/platform.h"
//#include "mbedtls/net_sockets.h"
//#include "mbedtls/esp_debug.h"
//#include "mbedtls/ssl.h"
//#include "mbedtls/error.h"

static const char* TAG = "BLE_ADV_SCAN";

#define SCAN_LOCAL_NAME_MAX_LEN 32
#define HCI_LE_ADV_REPORT_EXT                       (0x09)


typedef struct
{
    char    scan_local_name[SCAN_LOCAL_NAME_MAX_LEN];
    uint8_t name_len;
} ble_scan_local_name_t;

typedef struct
{
    uint8_t* q_data;
    uint16_t q_data_len;
} host_rcv_data_t;

static uint8_t hci_cmd_buf[128];

static uint16_t      scanned_count = 0;
static QueueHandle_t adv_queue;

/* start AES */

/**
* AES-CTR decryptie.
*
* @param key AES key (16, 24 of 32 bytes)
* @param key_len Lengte van de key in bytes
* @param nonce_counter 16-byte nonce/counter waarde
* @param input Versleutelde data
* @param output Buffer voor ontsleutelde data
* @param length Lengte van de data (max 32 bytes)
*
* @return 0 bij succes, negatieve waarde bij fout
*/

int aes_ctr_decrypt(
    const uint8_t *key,
    size_t         key_len,
    const uint8_t  nonce_counter[16],
    const uint8_t *input,
    uint8_t       *output,
    size_t         length)
{
    if ((key_len != 16) &&
        (key_len != 24) &&
        (key_len != 32))
    {
        return -1;
    }

    if (length > 32)
    {
        return -2;
    }

    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

    /*
     * Describe the AES key.
     */
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);

    /*
     * Import the raw AES key.
     */
    status = psa_import_key(
        &attributes,
        key,
        key_len,
        &key_id);

    psa_reset_key_attributes(&attributes);

    if (status != PSA_SUCCESS)
    {
        return -3;
    }

    /*
     * Start AES-CTR operation.
     */
    status = psa_cipher_decrypt_setup(
        &operation,
        key_id,
        PSA_ALG_CTR);

    if (status != PSA_SUCCESS)
    {
        psa_destroy_key(key_id);
        return -4;
    }

    /*
     * PSA expects the IV/nonce separately.
     */
    status = psa_cipher_set_iv(
        &operation,
        nonce_counter,
        16);

    if (status != PSA_SUCCESS)
    {
        psa_cipher_abort(&operation);
        psa_destroy_key(key_id);
        return -5;
    }

    /*
     * Decrypt the data.
     */
    size_t output_len = 0;

    status = psa_cipher_update(
        &operation,
        input,
        length,
        output,
        length,
        &output_len);

    if (status != PSA_SUCCESS)
    {
        psa_cipher_abort(&operation);
        psa_destroy_key(key_id);
        return -6;
    }

    /*
     * Finish the operation.
     */
    size_t finish_len = 0;

    status = psa_cipher_finish(
        &operation,
        output + output_len,
        length - output_len,
        &finish_len);

    if (status != PSA_SUCCESS)
    {
        psa_cipher_abort(&operation);
        psa_destroy_key(key_id);
        return -7;
    }

    output_len += finish_len;

    psa_destroy_key(key_id);

    /*
     * AES-CTR does not add/remove padding, so this should
     * normally equal length.
     */
    if (output_len != length)
    {
        return -8;
    }

    return 0;
}

/* end AES */

static void periodic_timer_callback(void* arg)
{
    ESP_LOGI(TAG, "Number of received advertising reports: %d", scanned_count);
}

/*
 * @brief: BT controller callback function, used to notify the upper layer that
 *         controller is ready to receive command
 */
static void controller_rcv_pkt_ready(void)
{
    ESP_LOGI(TAG, "controller rcv pkt ready");
}

/*
 * @brief: BT controller callback function to transfer data packet to
 *         the host
 */
static int host_rcv_pkt(uint8_t* data, uint16_t len)
{
    host_rcv_data_t send_data;
    uint8_t*        data_pkt;
    /* Check second byte for HCI event. If event opcode is 0x0e, the event is
     * HCI Command Complete event. Sice we have received "0x0e" event, we can
     * check for byte 4 for command opcode and byte 6 for it's return status. */
    if (data[1] == 0x0e)
    {
        if (data[6] == 0)
        {
            esp_rom_printf("Event opcode 0x%02x success.", data[4]);
        }
        else
        {
            esp_rom_printf("Event opcode 0x%02x fail with reason: 0x%02x.", data[4], data[6]);
            return ESP_FAIL;
        }
    }

    data_pkt = (uint8_t*) malloc(sizeof(uint8_t) * len);
    if (data_pkt == NULL)
    {
        esp_rom_printf("Malloc data_pkt failed!");
        return ESP_FAIL;
    }
    memcpy(data_pkt, data, len);
    send_data.q_data     = data_pkt;
    send_data.q_data_len = len;
    if (xQueueSend(adv_queue, (void*) &send_data, (TickType_t) 0) != pdTRUE)
    {
        esp_rom_printf("Failed to enqueue advertising report. Queue full.");
        /* If data sent successfully, then free the pointer in `xQueueReceive'
         * after processing it. Or else if enqueue in not successful, free it
         * here. */
        free(data_pkt);
    }
    return ESP_OK;
}

static esp_vhci_host_callback_t vhci_host_cb = {
    controller_rcv_pkt_ready,
    host_rcv_pkt};

static void hci_cmd_send_reset(void)
{
    uint16_t sz = make_cmd_reset(hci_cmd_buf);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
}

static void hci_cmd_send_set_evt_mask(void)
{
    /* Set bit 61 in event mask to enable LE Meta events. */
    uint8_t  evt_mask[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20};
    uint16_t sz          = make_cmd_set_evt_mask(hci_cmd_buf, evt_mask);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
}

static void hci_cmd_send_ble_scan_params(void)
{
    /* Set scan type to 0x01 for active scanning and 0x00 for passive scanning. */
    uint8_t scan_type = 0x01;

    /* Scan window and Scan interval are set in terms of number of slots. Each slot is of 625 microseconds. */
    uint16_t scan_interval = 50; /* 50 ms */
    uint16_t scan_window   = 49; /* 30 ms */

    uint8_t  own_addr_type = 0x00; /* Public Device Address (default). */
    uint8_t  filter_policy = 0x00; /* Accept all packets except directed advertising packets (default). */
    uint16_t sz            = make_cmd_ble_set_scan_params(hci_cmd_buf, scan_type, scan_interval, scan_window, own_addr_type, filter_policy);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
}

static void hci_cmd_send_ble_scan_start(void)
{
    uint8_t  scan_enable       = 0x01; /* Scanning enabled. */
    uint8_t  filter_duplicates = 0x01; /* Duplicate filtering enabled. */
    uint16_t sz                = make_cmd_ble_set_scan_enable(hci_cmd_buf, scan_enable, filter_duplicates);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
    ESP_LOGI(TAG, "BLE Scanning started..");
}

static void hci_cmd_send_ble_adv_start(void)
{
    uint16_t sz = make_cmd_ble_set_adv_enable(hci_cmd_buf, 1);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
    ESP_LOGI(TAG, "BLE Advertising started..");
}

static void hci_cmd_send_ble_set_adv_param(void)
{
    /* Minimum and maximum Advertising interval are set in terms of slots. Each slot is of 625 microseconds. */
    uint16_t adv_intv_min = 0x100;
    uint16_t adv_intv_max = 0x100;

    /* Connectable undirected advertising (ADV_IND). */
    uint8_t adv_type = 0;

    /* Own address is public address. */
    uint8_t own_addr_type = 0;

    /* Public Device Address */
    uint8_t peer_addr_type = 0;
    uint8_t peer_addr[6]   = {0xF7, 0xE8, 0xD6, 0xC8, 0x88, 0x49};

    /* Channel 37, 38 and 39 for advertising. */
    uint8_t adv_chn_map = 0x07;

    /* Process scan and connection requests from all devices (i.e., the White List is not in use). */
    uint8_t adv_filter_policy = 0x00;

    uint16_t sz = make_cmd_ble_set_adv_param(hci_cmd_buf,
                                             adv_intv_min,
                                             adv_intv_max,
                                             adv_type,
                                             own_addr_type,
                                             peer_addr_type,
                                             peer_addr,
                                             adv_chn_map,
                                             adv_filter_policy);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
}

static void hci_cmd_send_ble_set_adv_data(void)
{
    char*   adv_name     = "ESP-BLE-1";
    uint8_t name_len     = (uint8_t) strlen(adv_name);
    uint8_t adv_data[31] = {0x02, 0x01, 0x06, 0x0, 0x09};
    uint8_t adv_data_len;

    adv_data[3] = name_len + 1;
    for (int i = 0; i < name_len; i++)
    {
        adv_data[5 + i] = (uint8_t) adv_name[i];
    }
    adv_data_len = 5 + name_len;

    uint16_t sz = make_cmd_ble_set_adv_data(hci_cmd_buf, adv_data_len, (uint8_t*) adv_data);
    esp_vhci_host_send_packet(hci_cmd_buf, sz);
    ESP_LOGI(TAG, "Starting BLE advertising with name \"%s\"", adv_name);
}

static esp_err_t get_local_name(uint8_t* data_msg, uint8_t data_len, ble_scan_local_name_t* scanned_packet)
{
    uint8_t curr_ptr = 0;

    /* Initialize output structure */
    scanned_packet->name_len           = 0;
    scanned_packet->scan_local_name[0] = '\0';

    while (curr_ptr < data_len)
    {
        /* Ensure there is at least 1 byte for length field */
        if (curr_ptr >= data_len)
        {
            return ESP_FAIL;
        }
        uint8_t curr_len = data_msg[curr_ptr++];

        /* Length of 0 indicates end of AD structures or invalid data */
        if (curr_len == 0)
        {
            return ESP_FAIL;
        }

        /* Ensure there is at least 1 byte for type field */
        if (curr_ptr >= data_len)
        {
            return ESP_FAIL;
        }
        uint8_t curr_type = data_msg[curr_ptr++];

        /* Calculate data field length (curr_len includes type byte) */
        uint8_t data_field_len = curr_len - 1;

        /* Verify remaining buffer has enough data */
        if (curr_ptr + data_field_len > data_len)
        {
            return ESP_FAIL;
        }

        /* Check for Local Name type (0x08: Shortened, 0x09: Complete) */
        if (curr_type == 0x08 || curr_type == 0x09)
        {
            /* Limit copy length to prevent buffer overflow */
            uint8_t copy_len = data_field_len;
            if (copy_len > SCAN_LOCAL_NAME_MAX_LEN - 1)
            {
                copy_len = SCAN_LOCAL_NAME_MAX_LEN - 1;
            }

            memcpy(scanned_packet->scan_local_name, &data_msg[curr_ptr], copy_len);
            scanned_packet->scan_local_name[copy_len] = '\0'; /* Ensure null termination */
            scanned_packet->name_len                  = copy_len;
            return ESP_OK;
        }

        /* Move to next AD structure */
        curr_ptr += data_field_len;
    }

    return ESP_FAIL;
}

void hci_evt_process(void* pvParameters)
{
    host_rcv_data_t rcv_data;

    while (1)
    {
        memset(&rcv_data, 0, sizeof(rcv_data));

        if (xQueueReceive(adv_queue, &rcv_data, portMAX_DELAY) != pdPASS)
        {
            ESP_LOGE(TAG, "Queue receive error");
            continue;
        }

        uint8_t* p   = rcv_data.q_data;
        uint16_t len = rcv_data.q_data_len;

        if (p == NULL || len < 4)
        {
            ESP_LOGW(TAG, "Invalid HCI packet, len=%u", len);
            free(p);
            continue;
        }

        /*
         * HCI Event packet:
         *
         *   byte 0: HCI packet type = 0x04
         *   byte 1: event code
         *   byte 2: parameter length
         *   byte 3: first event parameter
         */
        if (p[0] != 0x04)
        {
            free(p);
            continue;
        }

        uint8_t event_code = p[1];
        uint8_t param_len  = p[2];

        if ((uint16_t) param_len + 3 > len)
        {
            ESP_LOGW(TAG,
                     "Invalid HCI event length: packet=%u parameter=%u",
                     len,
                     param_len);
            free(p);
            continue;
        }

        /*
         * LE Meta Event
         */
        if (event_code != LE_META_EVENTS)
        {
            free(p);
            continue;
        }

        if (param_len < 1)
        {
            free(p);
            continue;
        }

        uint8_t sub_event = p[3];

        /*
         * We support:
         *
         *   LE Advertising Report
         *
         * Your original code accidentally tested the extended event
         * constant twice.
         */
        if (sub_event == HCI_LE_ADV_REPORT)
        {
            /*
             * Legacy LE Advertising Report
             *
             * Parameters:
             *   +0  subevent
             *   +1  Num_Reports
             *
             * Each report:
             *   Event_Type       1
             *   Address_Type     1
             *   Address          6
             *   Data_Length      1
             *   Data             N
             *   RSSI             1
             */

            if (param_len < 2)
            {
                free(p);
                continue;
            }

            uint8_t  num_reports = p[4];
            uint16_t offset      = 5;

            for (uint8_t i = 0; i < num_reports; i++)
            {
                /*
                 * Fixed part before advertising data:
                 * Event type + address type + address + data length
                 */
                if (offset + 9 > len)
                {
                    ESP_LOGW(TAG, "Truncated legacy advertising report");
                    break;
                }

                uint8_t event_type = p[offset++];
                uint8_t addr_type  = p[offset++];

                uint8_t addr[6];
                memcpy(addr, &p[offset], 6);
                offset += 6;

                uint8_t data_len = p[offset++];

                /*
                 * Data + RSSI must both be present.
                 */
                if (offset + data_len + 1 > len)
                {
                    ESP_LOGW(TAG,
                             "Truncated advertising data: data_len=%u",
                             data_len);
                    break;
                }

                uint8_t* adv_data = &p[offset];
                offset += data_len;

                int8_t rssi = (int8_t) p[offset++];

                scanned_count++;

                /*
                 * Extract local name from this report only.
                 */
                ble_scan_local_name_t name;

                esp_err_t name_ret =
                    get_local_name(adv_data, data_len, &name);

                printf("******** Advertising Report %u/%u ********\n",
                       i + 1,
                       num_reports);

                printf("Event type: %02X\n", event_type);
                printf("Address type: %02X\n", addr_type);

                printf("Address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       addr[5],
                       addr[4],
                       addr[3],
                       addr[2],
                       addr[1],
                       addr[0]);

                printf("Data length: %u\n", data_len);

                printf("Data: ");
                for (uint8_t j = 0; j < data_len; j++)
                {
                    printf("%02X ", adv_data[j]);
                }
                printf("\n");

                if (name_ret == ESP_OK)
                {
                    printf("Advertisement Name: %.*s\n",
                           name.name_len,
                           name.scan_local_name);
                }
                else
                {
                    printf("Advertisement Name: <none>\n");
                }

                printf("RSSI: %d dBm\n", rssi);
            }
        }
        
        /*
         * Optional debugging of the complete HCI event.
         */

        printf("Raw HCI:");
        for (uint16_t i = 0; i < len; i++)
            printf(" %02X", p[i]);
        printf("\n");

        free(p);
    }
}

void hci_evt_process_original(void* pvParameters)
{
    host_rcv_data_t* rcv_data = (host_rcv_data_t*) malloc(sizeof(host_rcv_data_t));
    if (rcv_data == NULL)
    {
        ESP_LOGE(TAG, "Malloc rcv_data failed!");
        return;
    }
    esp_err_t ret;

    while (1)
    {
        uint8_t                sub_event, num_responses, total_data_len, data_msg_ptr, hci_event_opcode;
        uint8_t *              queue_data = NULL, *event_type = NULL, *addr_type = NULL, *addr = NULL, *data_len = NULL, *data_msg = NULL;
        short int*             rssi = NULL;
        uint16_t               data_ptr;
        ble_scan_local_name_t* scanned_name = NULL;
        total_data_len                      = 0;
        data_msg_ptr                        = 0;
        if (xQueueReceive(adv_queue, rcv_data, portMAX_DELAY) != pdPASS)
        {
            ESP_LOGE(TAG, "Queue receive error");
        }
        else
        {
            /* `data_ptr' keeps track of current position in the received data. */
            data_ptr   = 0;
            queue_data = rcv_data->q_data;

            /* Parsing `data' and copying in various fields. */
            hci_event_opcode = queue_data[++data_ptr];
            if (hci_event_opcode == LE_META_EVENTS)
            {
                /* Set `data_ptr' to 4th entry, which will point to sub event. */
                data_ptr += 2;
                sub_event = queue_data[data_ptr++];
                /* Check if sub event is LE advertising report event. */
                if ((sub_event == HCI_LE_ADV_REPORT) || (sub_event == HCI_LE_ADV_REPORT_EXT))
                {
                    scanned_count += 1;

                    /* Get number of advertising reports. */
                    num_responses = queue_data[data_ptr++];
                    event_type    = (uint8_t*) malloc(sizeof(uint8_t) * num_responses);
                    if (event_type == NULL)
                    {
                        ESP_LOGE(TAG, "Malloc event_type failed!");
                        goto reset;
                    }
                    for (uint8_t i = 0; i < num_responses; i += 1)
                    {
                        event_type[i] = queue_data[data_ptr++];
                    }

                    /* Get advertising type for every report. */
                    addr_type = (uint8_t*) malloc(sizeof(uint8_t) * num_responses);
                    if (addr_type == NULL)
                    {
                        ESP_LOGE(TAG, "Malloc addr_type failed!");
                        goto reset;
                    }
                    for (uint8_t i = 0; i < num_responses; i += 1)
                    {
                        addr_type[i] = queue_data[data_ptr++];
                    }

                    /* Get BD address in every advetising report and store in
                     * single array of length `6 * num_responses' as each address
                     * will take 6 spaces. */
                    addr = (uint8_t*) malloc(sizeof(uint8_t) * 6 * num_responses);
                    if (addr == NULL)
                    {
                        ESP_LOGE(TAG, "Malloc addr failed!");
                        goto reset;
                    }
                    for (int i = 0; i < num_responses; i += 1)
                    {
                        for (int j = 0; j < 6; j += 1)
                        {
                            addr[(6 * i) + j] = queue_data[data_ptr++];
                        }
                    }

                    /* Get length of data for each advertising report. */
                    data_len = (uint8_t*) malloc(sizeof(uint8_t) * num_responses);
                    if (data_len == NULL)
                    {
                        ESP_LOGE(TAG, "Malloc data_len failed!");
                        goto reset;
                    }
                    for (uint8_t i = 0; i < num_responses; i += 1)
                    {
                        data_len[i] = queue_data[data_ptr];
                        total_data_len += queue_data[data_ptr++];
                    }

                    if (total_data_len != 0)
                    {
                        /* Get all data packets. */
                        data_msg = (uint8_t*) malloc(sizeof(uint8_t) * total_data_len);
                        if (data_msg == NULL)
                        {
                            ESP_LOGE(TAG, "Malloc data_msg failed!");
                            goto reset;
                        }
                        for (uint8_t i = 0; i < num_responses; i += 1)
                        {
                            for (uint8_t j = 0; j < data_len[i]; j += 1)
                            {
                                data_msg[data_msg_ptr++] = queue_data[data_ptr++];
                            }
                        }
                    }

                    /* Counts of advertisements done. This count is set in advertising data every time before advertising. */
                    rssi = (short int*) malloc(sizeof(short int) * num_responses);
                    if (rssi == NULL)
                    {
                        ESP_LOGE(TAG, "Malloc rssi failed!");
                        goto reset;
                    }
                    for (uint8_t i = 0; i < num_responses; i += 1)
                    {
                        rssi[i] = -(0xFF - queue_data[data_ptr++]);
                    }

                    /* Extracting advertiser's name. */
                    data_msg_ptr = 0;
                    scanned_name = (ble_scan_local_name_t*) malloc(num_responses * sizeof(ble_scan_local_name_t));
                    if (scanned_name == NULL)
                    {
                        ESP_LOGE(TAG, "Malloc scanned_name failed!");
                        goto reset;
                    }
                    for (uint8_t i = 0; i < num_responses; i += 1)
                    {
                        ret = get_local_name(&data_msg[data_msg_ptr], data_len[i], scanned_name);

                        /* Print the data if adv report has a valid name. */
                        if (ret == ESP_OK)
                        {
                            printf("******** Response %d/%d ********\n", i + 1, num_responses);
                            printf("Event type: %02x\nAddress type: %02x\nAddress: ", event_type[i], addr_type[i]);
                            for (int j = 5; j >= 0; j -= 1)
                            {
                                printf("%02x", addr[(6 * i) + j]);
                                if (j > 0)
                                {
                                    printf(":");
                                }
                            }

                            printf("\nData length: %d\nData: ", data_len[i]);
                            data_msg_ptr += data_len[i];

                            /* Print all data. */
                            for (int j = 0; j < data_len[i]; j++)
                                printf("%02X ", data_msg[data_msg_ptr + j]);

                            printf("\nAdvertisement Name: ");
                            for (int k = 0; k < scanned_name->name_len; k += 1)
                            {
                                printf("%c", scanned_name->scan_local_name[k]);
                            }
                            printf("\nRSSI: %ddB\n", rssi[i]);
                        }
                    }

                    /* Freeing all spaces allocated. */
                reset:
                    free(scanned_name);
                    free(rssi);
                    free(data_msg);
                    free(data_len);
                    free(addr);
                    free(addr_type);
                    free(event_type);
                }
            }
            /* #if (CONFIG_LOG_DEFAULT_LEVEL_DEBUG || CONFIG_LOG_DEFAULT_LEVEL_VERBOSE) */
            printf("Raw Data:");
            for (uint8_t j = 0; j < rcv_data->q_data_len; j += 1)
            {
                printf(" %02x", queue_data[j]);
            }
            printf("\nQueue free size: %d\n", uxQueueSpacesAvailable(adv_queue));
            /* #endif */
            free(queue_data);
        }
        memset(rcv_data, 0, sizeof(host_rcv_data_t));
    }
}

void app_main(void)
{
    /* start AES */

    psa_status_t status = psa_crypto_init();

    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG,
                 "PSA crypto initialization failed: %ld",
                 (long)status);
        return;
    }

    uint8_t key[16] = {
        0x2B, 0x7E, 0x15, 0x16,
        0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88,
        0x09, 0xCF, 0x4F, 0x3C
    };

    uint8_t nonce_counter[16] = {
        0xF0, 0xF1, 0xF2, 0xF3,
        0xF4, 0xF5, 0xF6, 0xF7,
        0xF8, 0xF9, 0xFA, 0xFB,
        0xFC, 0xFD, 0xFE, 0xFF
    };

    uint8_t encrypted[32];
    uint8_t decrypted[32];

    int ret_aes = aes_ctr_decrypt(
        key,
        sizeof(key),
        nonce_counter,
        encrypted,
        decrypted,
        sizeof(encrypted));

    if (ret_aes != 0)
    {
        ESP_LOGE(TAG, "AES-CTR decrypt failed: %d", ret_aes);
    }
    /* end AES */

    bool continue_commands = 1;
    int  cmd_cnt           = 0;

    const esp_timer_create_args_t periodic_timer_args = {
        .callback = &periodic_timer_callback,
        .name     = "periodic"};

    /* Create timer for logging scanned devices. */
    esp_timer_handle_t periodic_timer;
    ESP_ERROR_CHECK(esp_timer_create(&periodic_timer_args, &periodic_timer));

    /* Start periodic timer for 5 sec. */
    ESP_ERROR_CHECK(esp_timer_start_periodic(periodic_timer, 5000000));

    /* Initialize NVS — it is used to store PHY calibration data */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();

    ret = esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    if (ret)
    {
        ESP_LOGI(TAG, "Bluetooth controller release classic bt memory failed: %s", esp_err_to_name(ret));
        return;
    }

    if ((ret = esp_bt_controller_init(&bt_cfg)) != ESP_OK)
    {
        ESP_LOGI(TAG, "Bluetooth controller initialize failed: %s", esp_err_to_name(ret));
        return;
    }

    if ((ret = esp_bt_controller_enable(ESP_BT_MODE_BLE)) != ESP_OK)
    {
        ESP_LOGI(TAG, "Bluetooth controller enable failed: %s", esp_err_to_name(ret));
        return;
    }

    /* A queue for storing received HCI packets. */
    adv_queue = xQueueCreate(15, sizeof(host_rcv_data_t));
    if (adv_queue == NULL)
    {
        ESP_LOGE(TAG, "Queue creation failed");
        return;
    }

    esp_vhci_host_register_callback(&vhci_host_cb);
    while (continue_commands)
    {
        if (continue_commands && esp_vhci_host_check_send_available())
        {
            switch (cmd_cnt)
            {
                case 0:
                    hci_cmd_send_reset();
                    ++cmd_cnt;
                    break;
                case 1:
                    hci_cmd_send_set_evt_mask();
                    ++cmd_cnt;
                    break;

                /* Send advertising commands. */
                case 2:
                    hci_cmd_send_ble_set_adv_param();
                    ++cmd_cnt;
                    break;
                case 3:
                    hci_cmd_send_ble_set_adv_data();
                    ++cmd_cnt;
                    break;
                case 4:
                    hci_cmd_send_ble_adv_start();
                    ++cmd_cnt;
                    break;

                /* Send scan commands. */
                case 5:
                    hci_cmd_send_ble_scan_params();
                    ++cmd_cnt;
                    break;
                case 6:
                    hci_cmd_send_ble_scan_start();
                    ++cmd_cnt;
                    break;
                default:
                    continue_commands = 0;
                    break;
            }
            ESP_LOGI(TAG, "BLE Advertise, cmd_sent: %d", cmd_cnt);
        }
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    xTaskCreatePinnedToCore(&hci_evt_process, "hci_evt_process", 2048, NULL, 6, NULL, 0);
}
