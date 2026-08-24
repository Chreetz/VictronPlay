idf_component_register(SRCS "victron.c" "app_bt.c"
                    PRIV_REQUIRES bt nvs_flash mbedtls
                    INCLUDE_DIRS ".")
