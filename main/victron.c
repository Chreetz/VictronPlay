/* chatgpt generated */

/* https://github.com/mk4001/VE-Display */

#include <stdio.h>
#include <stdint.h>

bool is_victron_advertisement(const uint8_t *data, uint8_t len)
{
    uint8_t pos = 0;

    while (pos < len)
    {
        uint8_t field_len = data[pos++];

        if (field_len == 0)
            break;

        if (pos + field_len > len)
            break;

        uint8_t type = data[pos];

        /*
         * Manufacturer Specific Data
         */
        if (type == 0xFF && field_len >= 3)
        {
            /*
             * Company ID is little-endian:
             *
             * E1 02 = 0x02E1 = Victron Energy BV
             */
            uint16_t company_id =
                (uint16_t)data[pos + 1] |
                ((uint16_t)data[pos + 2] << 8);

            if (company_id == 0x02E1)
                return true;
        }

        pos += field_len;
    }

    return false;
}

/*

Offset   Length   Meaning
------   ------   ---------------------------
0        2        Company ID
2        1        Record type
3        2        Product ID
5        1        Readout type
6        1        Victron data record type
7        2        Counter/nonce
9        1        Key-check byte
10       ...      AES-CTR encrypted payload


bits 0..7       Device State
bits 8..15      Error Code
bits 16..31     Output Voltage
bits 32..47     Output Current
bits 48..63     Input Voltage
bits 64..79     Input Current
bits 80..111    Device Off Reason

https://community.victronenergy.com/t/orion-xs-12v-12v-50a-bluetooth-advertising-data/2183

*/

bool get_victron_data(
    const uint8_t *data,
    uint8_t len,
    const uint8_t **victron_data,
    uint8_t *victron_len)
{
    uint8_t pos = 0;

    while (pos < len)
    {
        uint8_t field_len = data[pos++];

        if (field_len == 0)
            break;

        if (pos + field_len > len)
            break;

        uint8_t type = data[pos];

        if (type == 0xFF && field_len >= 3)
        {
            uint16_t company_id =
                (uint16_t)data[pos + 1] |
                ((uint16_t)data[pos + 2] << 8);

            if (company_id == 0x02E1)
            {
                /*
                 * Skip:
                 *   type       1 byte
                 *   company ID 2 bytes
                 *
                 * What remains is Victron's manufacturer data.
                 */
                *victron_data = &data[pos + 3];
                *victron_len = field_len - 3;

                return true;
            }
        }

        pos += field_len;
    }

    return false;
}
