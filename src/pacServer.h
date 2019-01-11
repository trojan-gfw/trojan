#include <microhttpd.h>
#include "log.h"

#ifndef DEFAULT_PAC_CONFIG
#define DEFAULT_PAC_CONFIG "pac.conf"
#endif // DEFAULT_PAC_CONFIG

char *pac_fcontent = NULL;
uint16_t pac_local_port = 0;

int createPacData(const char *fileUri, char **pacContent) {

    int ret = 0;
    (*pacContent) = NULL;


    FILE *fp;
    fp = fopen(fileUri, "r");
    if (fp == NULL) {
        Log::log_with_date_time("pac.conf file open failed.", Log::FATAL);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize) {
        (*pacContent) = (char *) malloc(fsize + 100);
        int seek = sprintf((*pacContent), "var proxy = \"SOCKS5 127.0.0.1:%d\"; \n", pac_local_port);

        if (seek > 0) {
            long readsize = fread((*pacContent) + seek, 1, fsize, fp);
            if (readsize <= 0) {
                Log::log_with_date_time("The content of the pac.conf file is abnormally read..", Log::FATAL);
                ret = -1;
            }
        } else {
            Log::log_with_date_time("Initialization of pac sock5 server failed.", Log::FATAL);
            ret = -1;
        }

    } else {
        Log::log_with_date_time("Pac.conf file size failed to get.", Log::FATAL);
        ret = -1;
    }

    if (ret == -1) {
        Log::log_with_date_time("Pac data construction failed.", Log::FATAL);
        if ((*pacContent) != NULL) {
            free((*pacContent));
            (*pacContent) = NULL;
        }
    }

    fclose(fp);

    return ret;
}

static int
answer_to_connection(void *cls, struct MHD_Connection *connection,
                     const char *url, const char *method,
                     const char *version, const char *upload_data,
                     size_t *upload_data_size, void **con_cls) {


    struct MHD_Response *response;
    int ret;

    if (pac_fcontent == NULL) {

        Log::log_with_date_time("Start constructing PAC data.", Log::INFO);
        int pacDataStatus = createPacData(DEFAULT_PAC_CONFIG, &pac_fcontent);
        if (pacDataStatus == -1) {
            Log::log_with_date_time("PAC data preparation failed.", Log::FATAL);
        }
    }


    if (pac_fcontent != NULL) {
        response = MHD_create_response_from_buffer(strlen(pac_fcontent), (void *) pac_fcontent,
                                                   MHD_RESPMEM_PERSISTENT);
    } else {
        const char *errreponse = "PAC data preparation failed.";
        response = MHD_create_response_from_buffer(strlen(errreponse), (void *) errreponse,
                                                   MHD_RESPMEM_PERSISTENT);
    }

    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;

}

int
startPacServer(uint16_t pacServerPort) {

    struct MHD_Daemon *daemon;

    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, pacServerPort, NULL, NULL,
                              &answer_to_connection, NULL, MHD_OPTION_END);
    if (NULL == daemon)
        return -1;

    //MHD_stop_daemon (daemon);
    return 0;
}
