#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define PRINT_IF_PRESENT(NAME) do \
        { \
            if (NAME.present) \
            { \
                printf("%s=%s\n", #NAME, NAME.value); \
            } \
        } while(0)

// TODO: change strcpy to STRSCPY
#define SET_CFG(NAME, VAL) do \
        { \
            if (VAL[strlen(VAL) - 1] == '\n') VAL[strlen(VAL) - 1] = '\0'; \
            strcpy(NAME.value, VAL); \
            NAME.present = true; \
        } while(0)

typedef struct hapd_cfg_field_t {
    char value[256];
    bool present;
} hapd_cfg_field_t;

struct hapd_cfg {
    hapd_cfg_field_t accept_mac_file;
    hapd_cfg_field_t ap_isolate;
    hapd_cfg_field_t ap_setup_locked;
    hapd_cfg_field_t auth_algs;
    hapd_cfg_field_t beacon_int;
    hapd_cfg_field_t bridge;
    hapd_cfg_field_t bssid;
    hapd_cfg_field_t bss_load_update_period;
    hapd_cfg_field_t bss_transition;
    hapd_cfg_field_t channel;
    hapd_cfg_field_t chan_util_avg_period;
    hapd_cfg_field_t config_methods;
    hapd_cfg_field_t country_code;
    hapd_cfg_field_t ctrl_interface;
    hapd_cfg_field_t disassoc_low_ack;
    hapd_cfg_field_t driver;
    hapd_cfg_field_t eap_server;
    hapd_cfg_field_t ht_capab;
    hapd_cfg_field_t hw_mode;
    hapd_cfg_field_t ieee80211ac;
    hapd_cfg_field_t ieee80211d;
    hapd_cfg_field_t ieee80211n;
    hapd_cfg_field_t interface;
    hapd_cfg_field_t ignore_broadcast_ssid;
    hapd_cfg_field_t logger_stdout;
    hapd_cfg_field_t logger_stdout_level;
    hapd_cfg_field_t logger_syslog;
    hapd_cfg_field_t logger_syslog_level;
    hapd_cfg_field_t macaddr_acl;
    hapd_cfg_field_t preamble;
    hapd_cfg_field_t rrm_neighbor_report;
    hapd_cfg_field_t ssid;
    hapd_cfg_field_t uapsd_advertisement_enabled;
    hapd_cfg_field_t vht_oper_centr_freq_seg0_idx;
    hapd_cfg_field_t vht_oper_chwidth;
    hapd_cfg_field_t wmm_enabled;
    hapd_cfg_field_t wpa;
    hapd_cfg_field_t wpa_key_mgmt;
    hapd_cfg_field_t wpa_pairwise;
    hapd_cfg_field_t wpa_passphrase;
    hapd_cfg_field_t wpa_psk_file;
    hapd_cfg_field_t wps_pin_requests;
    hapd_cfg_field_t wps_state;
} hapd_cfg;


static void print_hapd_cfg(struct hapd_cfg *cfg)
{
    PRINT_IF_PRESENT(cfg->accept_mac_file);
    PRINT_IF_PRESENT(cfg->ap_isolate);
    PRINT_IF_PRESENT(cfg->ap_setup_locked);
    PRINT_IF_PRESENT(cfg->auth_algs);
    PRINT_IF_PRESENT(cfg->beacon_int);
    PRINT_IF_PRESENT(cfg->bridge);
    PRINT_IF_PRESENT(cfg->bssid);
    PRINT_IF_PRESENT(cfg->bss_load_update_period);
    PRINT_IF_PRESENT(cfg->bss_transition);
    PRINT_IF_PRESENT(cfg->channel);
    PRINT_IF_PRESENT(cfg->chan_util_avg_period);
    PRINT_IF_PRESENT(cfg->config_methods);
    PRINT_IF_PRESENT(cfg->country_code);
    PRINT_IF_PRESENT(cfg->ctrl_interface);
    PRINT_IF_PRESENT(cfg->disassoc_low_ack);
    PRINT_IF_PRESENT(cfg->driver);
    PRINT_IF_PRESENT(cfg->eap_server);
    PRINT_IF_PRESENT(cfg->ht_capab);
    PRINT_IF_PRESENT(cfg->hw_mode);
    PRINT_IF_PRESENT(cfg->ieee80211ac);
    PRINT_IF_PRESENT(cfg->ieee80211d);
    PRINT_IF_PRESENT(cfg->ieee80211n);
    PRINT_IF_PRESENT(cfg->ignore_broadcast_ssid);
    PRINT_IF_PRESENT(cfg->interface);
    PRINT_IF_PRESENT(cfg->logger_stdout);
    PRINT_IF_PRESENT(cfg->logger_stdout_level);
    PRINT_IF_PRESENT(cfg->logger_syslog);
    PRINT_IF_PRESENT(cfg->logger_syslog_level);
    PRINT_IF_PRESENT(cfg->macaddr_acl);
    PRINT_IF_PRESENT(cfg->preamble);
    PRINT_IF_PRESENT(cfg->rrm_neighbor_report);
    PRINT_IF_PRESENT(cfg->ssid);
    PRINT_IF_PRESENT(cfg->uapsd_advertisement_enabled);
    PRINT_IF_PRESENT(cfg->vht_oper_centr_freq_seg0_idx);
    PRINT_IF_PRESENT(cfg->vht_oper_chwidth);
    PRINT_IF_PRESENT(cfg->wmm_enabled);
    PRINT_IF_PRESENT(cfg->wpa);
    PRINT_IF_PRESENT(cfg->wpa_key_mgmt);
    PRINT_IF_PRESENT(cfg->wpa_pairwise);
    PRINT_IF_PRESENT(cfg->wpa_passphrase);
    PRINT_IF_PRESENT(cfg->wpa_psk_file);
    PRINT_IF_PRESENT(cfg->wps_pin_requests);
    PRINT_IF_PRESENT(cfg->wps_state);
}

static void hapd_parse_line(char *line, struct hapd_cfg *cfg)
{
    char *key = NULL;
    char *value = NULL;

    key = strtok(line, "=");
    value = strtok(NULL, "=");

    if (!strcmp(key, "accept_mac_file")) SET_CFG(cfg->accept_mac_file, value);
    else if (!strcmp(key, "ap_isolate")) SET_CFG(cfg->ap_isolate, value);
    else if (!strcmp(key, "ap_setup_locked")) SET_CFG(cfg->ap_setup_locked, value);
    else if (!strcmp(key, "auth_algs")) SET_CFG(cfg->auth_algs, value);
    else if (!strcmp(key, "beacon_int")) SET_CFG(cfg->beacon_int, value);
    else if (!strcmp(key, "bridge")) SET_CFG(cfg->bridge, value);
    else if (!strcmp(key, "bssid")) SET_CFG(cfg->bssid, value);
    else if (!strcmp(key, "bss_load_update_period")) SET_CFG(cfg->bss_load_update_period, value);
    else if (!strcmp(key, "bss_transition")) SET_CFG(cfg->bss_transition, value);
    else if (!strcmp(key, "channel")) SET_CFG(cfg->country_code, value);
    else if (!strcmp(key, "chan_util_avg_period")) SET_CFG(cfg->chan_util_avg_period, value);
    else if (!strcmp(key, "config_methods")) SET_CFG(cfg->config_methods, value);
    else if (!strcmp(key, "country_code")) SET_CFG(cfg->country_code, value);
    else if (!strcmp(key, "ctrl_interface")) SET_CFG(cfg->ctrl_interface, value);
    else if (!strcmp(key, "disassoc_low_ack")) SET_CFG(cfg->disassoc_low_ack, value);
    else if (!strcmp(key, "driver")) SET_CFG(cfg->driver, value);
    else if (!strcmp(key, "eap_server")) SET_CFG(cfg->eap_server, value);
    else if (!strcmp(key, "ht_capab")) SET_CFG(cfg->ht_capab, value);
    else if (!strcmp(key, "hw_mode")) SET_CFG(cfg->hw_mode, value);
    else if (!strcmp(key, "ieee80211ac")) SET_CFG(cfg->ieee80211ac, value);
    else if (!strcmp(key, "ieee80211d")) SET_CFG(cfg->ieee80211d, value);
    else if (!strcmp(key, "ieee80211n")) SET_CFG(cfg->ieee80211n, value);
    else if (!strcmp(key, "interface")) SET_CFG(cfg->interface, value);
    else if (!strcmp(key, "ignore_broadcast_ssid")) SET_CFG(cfg->ignore_broadcast_ssid, value);
    else if (!strcmp(key, "logger_stdout")) SET_CFG(cfg->logger_stdout, value);
    else if (!strcmp(key, "logger_stdout_level")) SET_CFG(cfg->logger_stdout_level, value);
    else if (!strcmp(key, "logger_syslog")) SET_CFG(cfg->logger_syslog, value);
    else if (!strcmp(key, "logger_syslog_level")) SET_CFG(cfg->logger_syslog_level, value);
    else if (!strcmp(key, "macaddr_acl")) SET_CFG(cfg->macaddr_acl, value);
    else if (!strcmp(key, "preamble")) SET_CFG(cfg->preamble, value);
    else if (!strcmp(key, "rrm_neighbor_report")) SET_CFG(cfg->rrm_neighbor_report, value);
    else if (!strcmp(key, "ssid")) SET_CFG(cfg->ssid, value);
    else if (!strcmp(key, "uapsd_advertisement_enabled")) SET_CFG(cfg->uapsd_advertisement_enabled, value);
    else if (!strcmp(key, "vht_oper_centr_freq_seg0_idx")) SET_CFG(cfg->vht_oper_centr_freq_seg0_idx, value);
    else if (!strcmp(key, "vht_oper_chwidth")) SET_CFG(cfg->vht_oper_chwidth, value);
    else if (!strcmp(key, "wmm_enabled")) SET_CFG(cfg->wmm_enabled, value);
    else if (!strcmp(key, "wpa")) SET_CFG(cfg->wpa, value);
    else if (!strcmp(key, "wpa_key_mgmt")) SET_CFG(cfg->wpa_key_mgmt, value);
    else if (!strcmp(key, "wpa_pairwise")) SET_CFG(cfg->wpa_pairwise, value);
    else if (!strcmp(key, "wpa_passphrase")) SET_CFG(cfg->wpa_passphrase, value);
    else if (!strcmp(key, "wpa_psk_file")) SET_CFG(cfg->wpa_psk_file, value);
    else if (!strcmp(key, "wps_pin_requests")) SET_CFG(cfg->wps_pin_requests, value);
    else if (!strcmp(key, "wps_state")) SET_CFG(cfg->wps_state, value);
}

static int hapd_read_cfg(const char *filename, struct hapd_cfg *cfg)
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    stream = fopen(filename, "r");
    if (stream == NULL)
    {
	perror("fopen");
	return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    while ((nread = getline(&line, &len, stream)) != -1)
    {
        if (line[0] == '#' || strlen(line) == 0) continue;
        hapd_parse_line(line, cfg);
    }

    free(line);
    fclose(stream);

    return 0;
}

int main(int argc, char *argv[])
{
    struct hapd_cfg cfg;
    int ret;

    ret = hapd_read_cfg(argv[1], &cfg);

    if (!ret) print_hapd_cfg(&cfg);

    return ret ? 1 : 0;
}
