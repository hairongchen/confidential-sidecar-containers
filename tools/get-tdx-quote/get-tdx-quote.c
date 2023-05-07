#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "tdx_attest.h"


int main(int argc, char *argv[])
{
    uint32_t quote_size = 0;
    tdx_report_data_t report_data = {{0}};
    tdx_report_t tdx_report = {{0}};
    tdx_uuid_t selected_att_key_id = {0};
    uint8_t *p_quote_buf = NULL;
    FILE *fptr = NULL;

    //1. get report data to bind
    if (argc > 1) {
        if(strlen(argv[1]) != TDX_REPORT_DATA_SIZE){
            fprintf(stderr, "\nWrong size of report data %ld\n",strlen(argv[1]));
            return 1;
        }

        int i;
    	for (i = 0; i < TDX_REPORT_DATA_SIZE; i++)
		report_data.d[i] = argv[1][i];
    }

    //2. get report 
    if (TDX_ATTEST_SUCCESS != tdx_att_get_report(&report_data, &tdx_report)) {
        fprintf(stderr, "\nFailed to get the report\n");
        return 1;
    }

    //3. get quote
    if (TDX_ATTEST_SUCCESS != tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id,
        &p_quote_buf, &quote_size, 0)) {
        fprintf(stderr, "\nFailed to get the quote\n");
        return 1;
    }

    //4. print quote to stdout
    for (size_t i = 0; i < quote_size; i++) {
        fprintf(stdout, "%02x", (uint8_t) p_quote_buf[i]);
    }

    //5. clean up buffer
    tdx_att_free_quote(p_quote_buf);

    return 0;
}
