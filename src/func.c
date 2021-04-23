void* BIO_f_ssl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[0])(a, b, c, d);
}
void* BIO_new_buffer_ssl_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[1])(a, b, c, d);
}
void* BIO_new_ssl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[2])(a, b, c, d);
}
void* BIO_new_ssl_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[3])(a, b, c, d);
}
void* BIO_ssl_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[4])(a, b, c, d);
}
void* DTLS_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[5])(a, b, c, d);
}
void* DTLS_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[6])(a, b, c, d);
}
void* DTLS_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[7])(a, b, c, d);
}
void* DTLSv1_2_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[8])(a, b, c, d);
}
void* DTLSv1_2_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[9])(a, b, c, d);
}
void* DTLSv1_2_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[10])(a, b, c, d);
}
void* DTLSv1_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[11])(a, b, c, d);
}
void* DTLSv1_get_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[12])(a, b, c, d);
}
void* DTLSv1_handle_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[13])(a, b, c, d);
}
void* DTLSv1_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[14])(a, b, c, d);
}
void* DTLSv1_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[15])(a, b, c, d);
}
void* PEM_read_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[16])(a, b, c, d);
}
void* PEM_read_bio_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[17])(a, b, c, d);
}
void* PEM_write_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[18])(a, b, c, d);
}
void* PEM_write_bio_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[19])(a, b, c, d);
}
void* SSL_CIPHER_description(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[20])(a, b, c, d);
}
void* SSL_CIPHER_get_bits(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[21])(a, b, c, d);
}
void* SSL_CIPHER_get_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[22])(a, b, c, d);
}
void* SSL_CIPHER_get_kx_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[23])(a, b, c, d);
}
void* SSL_CIPHER_get_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[24])(a, b, c, d);
}
void* SSL_CIPHER_get_rfc_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[25])(a, b, c, d);
}
void* SSL_CIPHER_get_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[26])(a, b, c, d);
}
void* SSL_CIPHER_has_MD5_HMAC(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[27])(a, b, c, d);
}
void* SSL_CIPHER_is_AES(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[28])(a, b, c, d);
}
void* SSL_CIPHER_is_AESGCM(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[29])(a, b, c, d);
}
void* SSL_CIPHER_is_CHACHA20POLY1305(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[30])(a, b, c, d);
}
void* SSL_COMP_add_compression_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[31])(a, b, c, d);
}
void* SSL_COMP_get_compression_methods(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[32])(a, b, c, d);
}
void* SSL_COMP_get_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[33])(a, b, c, d);
}
void* SSL_CTX_add_client_CA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[34])(a, b, c, d);
}
void* SSL_CTX_add_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[35])(a, b, c, d);
}
void* SSL_CTX_check_private_key(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[36])(a, b, c, d);
}
void* SSL_CTX_clear_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[37])(a, b, c, d);
}
void* SSL_CTX_clear_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[38])(a, b, c, d);
}
void* SSL_CTX_ctrl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[39])(a, b, c, d);
}
void* SSL_CTX_enable_ocsp_stapling(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[40])(a, b, c, d);
}
void* SSL_CTX_enable_signed_cert_timestamps(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[41])(a, b, c, d);
}
void* SSL_CTX_enable_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[42])(a, b, c, d);
}
void* SSL_CTX_flush_sessions(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[43])(a, b, c, d);
}
void* SSL_CTX_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[44])(a, b, c, d);
}
void* SSL_CTX_get0_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[45])(a, b, c, d);
}
void* SSL_CTX_get0_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[46])(a, b, c, d);
}
void* SSL_CTX_get0_privatekey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[47])(a, b, c, d);
}
void* SSL_CTX_get_cert_store(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[48])(a, b, c, d);
}
void* SSL_CTX_get_channel_id_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[49])(a, b, c, d);
}
void* SSL_CTX_get_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[50])(a, b, c, d);
}
void* SSL_CTX_get_client_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[51])(a, b, c, d);
}
void* SSL_CTX_get_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[52])(a, b, c, d);
}
void* SSL_CTX_get_ex_new_index(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[53])(a, b, c, d);
}
void* SSL_CTX_get_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[54])(a, b, c, d);
}
void* SSL_CTX_get_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[55])(a, b, c, d);
}
void* SSL_CTX_get_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[56])(a, b, c, d);
}
void* SSL_CTX_get_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[57])(a, b, c, d);
}
void* SSL_CTX_get_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[58])(a, b, c, d);
}
void* SSL_CTX_get_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[59])(a, b, c, d);
}
void* SSL_CTX_get_session_cache_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[60])(a, b, c, d);
}
void* SSL_CTX_get_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[61])(a, b, c, d);
}
void* SSL_CTX_get_verify_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[62])(a, b, c, d);
}
void* SSL_CTX_get_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[63])(a, b, c, d);
}
void* SSL_CTX_get_verify_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[64])(a, b, c, d);
}
void* SSL_CTX_load_verify_locations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[65])(a, b, c, d);
}
void* SSL_CTX_need_tmp_RSA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[66])(a, b, c, d);
}
void* SSL_CTX_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[67])(a, b, c, d);
}
void* SSL_CTX_remove_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[68])(a, b, c, d);
}
void* SSL_CTX_sess_accept(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[69])(a, b, c, d);
}
void* SSL_CTX_sess_accept_good(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[70])(a, b, c, d);
}
void* SSL_CTX_sess_accept_renegotiate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[71])(a, b, c, d);
}
void* SSL_CTX_sess_cache_full(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[72])(a, b, c, d);
}
void* SSL_CTX_sess_cb_hits(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[73])(a, b, c, d);
}
void* SSL_CTX_sess_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[74])(a, b, c, d);
}
void* SSL_CTX_sess_connect_good(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[75])(a, b, c, d);
}
void* SSL_CTX_sess_connect_renegotiate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[76])(a, b, c, d);
}
void* SSL_CTX_sess_get_cache_size(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[77])(a, b, c, d);
}
void* SSL_CTX_sess_get_get_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[78])(a, b, c, d);
}
void* SSL_CTX_sess_get_new_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[79])(a, b, c, d);
}
void* SSL_CTX_sess_get_remove_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[80])(a, b, c, d);
}
void* SSL_CTX_sess_hits(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[81])(a, b, c, d);
}
void* SSL_CTX_sess_misses(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[82])(a, b, c, d);
}
void* SSL_CTX_sess_number(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[83])(a, b, c, d);
}
void* SSL_CTX_sess_set_cache_size(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[84])(a, b, c, d);
}
void* SSL_CTX_sess_set_get_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[85])(a, b, c, d);
}
void* SSL_CTX_sess_set_new_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[86])(a, b, c, d);
}
void* SSL_CTX_sess_set_remove_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[87])(a, b, c, d);
}
void* SSL_CTX_sess_timeouts(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[88])(a, b, c, d);
}
void* SSL_CTX_sessions(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[89])(a, b, c, d);
}
void* SSL_CTX_set1_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[90])(a, b, c, d);
}
void* SSL_CTX_set1_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[91])(a, b, c, d);
}
void* SSL_CTX_set_alpn_protos(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[92])(a, b, c, d);
}
void* SSL_CTX_set_alpn_select_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[93])(a, b, c, d);
}
void* SSL_CTX_set_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[94])(a, b, c, d);
}
void* SSL_CTX_set_cert_store(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[95])(a, b, c, d);
}
void* SSL_CTX_set_cert_verify_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[96])(a, b, c, d);
}
void* SSL_CTX_set_channel_id_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[97])(a, b, c, d);
}
void* SSL_CTX_set_cipher_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[98])(a, b, c, d);
}
void* SSL_CTX_set_cipher_list_tls11(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[99])(a, b, c, d);
}
void* SSL_CTX_set_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[100])(a, b, c, d);
}
void* SSL_CTX_set_client_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[101])(a, b, c, d);
}
void* SSL_CTX_set_default_passwd_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[102])(a, b, c, d);
}
void* SSL_CTX_set_default_passwd_cb_userdata(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[103])(a, b, c, d);
}
void* SSL_CTX_set_default_verify_paths(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[104])(a, b, c, d);
}
void* SSL_CTX_set_dos_protection_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[105])(a, b, c, d);
}
void* SSL_CTX_set_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[106])(a, b, c, d);
}
void* SSL_CTX_set_generate_session_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[107])(a, b, c, d);
}
void* SSL_CTX_set_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[108])(a, b, c, d);
}
void* SSL_CTX_set_keylog_bio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[109])(a, b, c, d);
}
void* SSL_CTX_set_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[110])(a, b, c, d);
}
void* SSL_CTX_set_max_send_fragment(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[111])(a, b, c, d);
}
void* SSL_CTX_set_max_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[112])(a, b, c, d);
}
void* SSL_CTX_set_min_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[113])(a, b, c, d);
}
void* SSL_CTX_set_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[114])(a, b, c, d);
}
void* SSL_CTX_set_msg_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[115])(a, b, c, d);
}
void* SSL_CTX_set_msg_callback_arg(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[116])(a, b, c, d);
}
void* SSL_CTX_set_next_proto_select_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[117])(a, b, c, d);
}
void* SSL_CTX_set_next_protos_advertised_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[118])(a, b, c, d);
}
void* SSL_CTX_set_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[119])(a, b, c, d);
}
void* SSL_CTX_set_psk_client_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[120])(a, b, c, d);
}
void* SSL_CTX_set_psk_server_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[121])(a, b, c, d);
}
void* SSL_CTX_set_purpose(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[122])(a, b, c, d);
}
void* SSL_CTX_set_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[123])(a, b, c, d);
}
void* SSL_CTX_set_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[124])(a, b, c, d);
}
void* SSL_CTX_set_session_cache_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[125])(a, b, c, d);
}
void* SSL_CTX_set_session_id_context(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[126])(a, b, c, d);
}
void* SSL_CTX_set_srtp_profiles(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[127])(a, b, c, d);
}
void* SSL_CTX_set_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[128])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_servername_arg(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[129])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_servername_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[130])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_ticket_key_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[131])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_use_srtp(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[132])(a, b, c, d);
}
void* SSL_CTX_set_tmp_dh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[133])(a, b, c, d);
}
void* SSL_CTX_set_tmp_dh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[134])(a, b, c, d);
}
void* SSL_CTX_set_tmp_ecdh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[135])(a, b, c, d);
}
void* SSL_CTX_set_tmp_ecdh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[136])(a, b, c, d);
}
void* SSL_CTX_set_tmp_rsa(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[137])(a, b, c, d);
}
void* SSL_CTX_set_tmp_rsa_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[138])(a, b, c, d);
}
void* SSL_CTX_set_trust(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[139])(a, b, c, d);
}
void* SSL_CTX_set_verify(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[140])(a, b, c, d);
}
void* SSL_CTX_set_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[141])(a, b, c, d);
}
void* SSL_CTX_use_PrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[142])(a, b, c, d);
}
void* SSL_CTX_use_PrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[143])(a, b, c, d);
}
void* SSL_CTX_use_PrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[144])(a, b, c, d);
}
void* SSL_CTX_use_RSAPrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[145])(a, b, c, d);
}
void* SSL_CTX_use_RSAPrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[146])(a, b, c, d);
}
void* SSL_CTX_use_RSAPrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[147])(a, b, c, d);
}
void* SSL_CTX_use_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[148])(a, b, c, d);
}
void* SSL_CTX_use_certificate_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[149])(a, b, c, d);
}
void* SSL_CTX_use_certificate_chain_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[150])(a, b, c, d);
}
void* SSL_CTX_use_certificate_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[151])(a, b, c, d);
}
void* SSL_CTX_use_psk_identity_hint(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[152])(a, b, c, d);
}
void* SSL_SESSION_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[153])(a, b, c, d);
}
void* SSL_SESSION_get0_peer(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[154])(a, b, c, d);
}
void* SSL_SESSION_get_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[155])(a, b, c, d);
}
void* SSL_SESSION_get_ex_new_index(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[156])(a, b, c, d);
}
void* SSL_SESSION_get_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[157])(a, b, c, d);
}
void* SSL_SESSION_get_time(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[158])(a, b, c, d);
}
void* SSL_SESSION_get_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[159])(a, b, c, d);
}
void* SSL_SESSION_get_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[160])(a, b, c, d);
}
void* SSL_SESSION_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[161])(a, b, c, d);
}
void* SSL_SESSION_print(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[162])(a, b, c, d);
}
void* SSL_SESSION_print_fp(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[163])(a, b, c, d);
}
void* SSL_SESSION_set1_id_context(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[164])(a, b, c, d);
}
void* SSL_SESSION_set_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[165])(a, b, c, d);
}
void* SSL_SESSION_set_time(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[166])(a, b, c, d);
}
void* SSL_SESSION_set_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[167])(a, b, c, d);
}
void* SSL_SESSION_to_bytes(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[168])(a, b, c, d);
}
void* SSL_SESSION_to_bytes_for_ticket(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[169])(a, b, c, d);
}
void* SSL_SESSION_up_ref(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[170])(a, b, c, d);
}
void* SSL_accept(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[171])(a, b, c, d);
}
void* SSL_add_client_CA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[172])(a, b, c, d);
}
void* SSL_add_dir_cert_subjects_to_stack(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[173])(a, b, c, d);
}
void* SSL_add_file_cert_subjects_to_stack(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[174])(a, b, c, d);
}
void* SSL_alert_desc_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[175])(a, b, c, d);
}
void* SSL_alert_desc_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[176])(a, b, c, d);
}
void* SSL_alert_type_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[177])(a, b, c, d);
}
void* SSL_alert_type_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[178])(a, b, c, d);
}
void* SSL_cache_hit(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[179])(a, b, c, d);
}
void* SSL_certs_clear(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[180])(a, b, c, d);
}
void* SSL_check_private_key(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[181])(a, b, c, d);
}
void* SSL_clear(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[182])(a, b, c, d);
}
void* SSL_clear_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[183])(a, b, c, d);
}
void* SSL_clear_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[184])(a, b, c, d);
}
void* SSL_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[185])(a, b, c, d);
}
void* SSL_ctrl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[186])(a, b, c, d);
}
void* SSL_cutthrough_complete(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[187])(a, b, c, d);
}
void* SSL_do_handshake(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[188])(a, b, c, d);
}
void* SSL_dup_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[189])(a, b, c, d);
}
void* SSL_early_callback_ctx_extension_get(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[190])(a, b, c, d);
}
void* SSL_enable_fastradio_padding(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[191])(a, b, c, d);
}
void* SSL_enable_ocsp_stapling(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[192])(a, b, c, d);
}
void* SSL_enable_signed_cert_timestamps(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[193])(a, b, c, d);
}
void* SSL_enable_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[194])(a, b, c, d);
}
void* SSL_export_keying_material(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[195])(a, b, c, d);
}
void* SSL_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[196])(a, b, c, d);
}
void* SSL_get0_alpn_selected(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[197])(a, b, c, d);
}
void* SSL_get0_next_proto_negotiated(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[198])(a, b, c, d);
}
void* SSL_get0_ocsp_response(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[199])(a, b, c, d);
}
void* SSL_get0_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[200])(a, b, c, d);
}
void* SSL_get0_signed_cert_timestamp_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[201])(a, b, c, d);
}
void* SSL_get1_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[202])(a, b, c, d);
}
void* SSL_get_SSL_CTX(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[203])(a, b, c, d);
}
void* SSL_get_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[204])(a, b, c, d);
}
void* SSL_get_cipher_by_value(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[205])(a, b, c, d);
}
void* SSL_get_cipher_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[206])(a, b, c, d);
}
void* SSL_get_ciphers(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[207])(a, b, c, d);
}
void* SSL_get_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[208])(a, b, c, d);
}
void* SSL_get_current_cipher(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[209])(a, b, c, d);
}
void* SSL_get_current_compression(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[210])(a, b, c, d);
}
void* SSL_get_current_expansion(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[211])(a, b, c, d);
}
void* SSL_get_default_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[212])(a, b, c, d);
}
void* SSL_get_error(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[213])(a, b, c, d);
}
void* SSL_get_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[214])(a, b, c, d);
}
void* SSL_get_ex_data_X509_STORE_CTX_idx(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[215])(a, b, c, d);
}
void* SSL_get_ex_new_index(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[216])(a, b, c, d);
}
void* SSL_get_fd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[217])(a, b, c, d);
}
void* SSL_get_finished(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[218])(a, b, c, d);
}
void* SSL_get_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[219])(a, b, c, d);
}
void* SSL_get_key_block_length(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[220])(a, b, c, d);
}
void* SSL_get_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[221])(a, b, c, d);
}
void* SSL_get_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[222])(a, b, c, d);
}
void* SSL_get_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[223])(a, b, c, d);
}
void* SSL_get_peer_cert_chain(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[224])(a, b, c, d);
}
void* SSL_get_peer_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[225])(a, b, c, d);
}
void* SSL_get_peer_finished(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[226])(a, b, c, d);
}
void* SSL_get_privatekey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[227])(a, b, c, d);
}
void* SSL_get_psk_identity(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[228])(a, b, c, d);
}
void* SSL_get_psk_identity_hint(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[229])(a, b, c, d);
}
void* SSL_get_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[230])(a, b, c, d);
}
void* SSL_get_rbio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[231])(a, b, c, d);
}
void* SSL_get_rc4_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[232])(a, b, c, d);
}
void* SSL_get_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[233])(a, b, c, d);
}
void* SSL_get_rfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[234])(a, b, c, d);
}
void* SSL_get_secure_renegotiation_support(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[235])(a, b, c, d);
}
void* SSL_get_selected_srtp_profile(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[236])(a, b, c, d);
}
void* SSL_get_servername(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[237])(a, b, c, d);
}
void* SSL_get_servername_type(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[238])(a, b, c, d);
}
void* SSL_get_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[239])(a, b, c, d);
}
void* SSL_get_shared_sigalgs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[240])(a, b, c, d);
}
void* SSL_get_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[241])(a, b, c, d);
}
void* SSL_get_sigalgs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[242])(a, b, c, d);
}
void* SSL_get_srtp_profiles(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[243])(a, b, c, d);
}
void* SSL_get_structure_sizes(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[244])(a, b, c, d);
}
void* SSL_get_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[245])(a, b, c, d);
}
void* SSL_get_tls_unique(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[246])(a, b, c, d);
}
void* SSL_get_verify_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[247])(a, b, c, d);
}
void* SSL_get_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[248])(a, b, c, d);
}
void* SSL_get_verify_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[249])(a, b, c, d);
}
void* SSL_get_verify_result(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[250])(a, b, c, d);
}
void* SSL_get_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[251])(a, b, c, d);
}
void* SSL_get_wbio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[252])(a, b, c, d);
}
void* SSL_get_wfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[253])(a, b, c, d);
}
void* SSL_has_matching_session_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[254])(a, b, c, d);
}
void* SSL_in_false_start(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[255])(a, b, c, d);
}
void* SSL_is_server(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[256])(a, b, c, d);
}
void* SSL_library_init(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[257])(a, b, c, d);
}
void* SSL_load_client_CA_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[258])(a, b, c, d);
}
void* SSL_load_error_strings(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[259])(a, b, c, d);
}
void* SSL_magic_pending_session_ptr(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[260])(a, b, c, d);
}
void* SSL_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[261])(a, b, c, d);
}
void* SSL_num_renegotiations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[262])(a, b, c, d);
}
void* SSL_peek(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[263])(a, b, c, d);
}
void* SSL_pending(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[264])(a, b, c, d);
}
void* SSL_read(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[265])(a, b, c, d);
}
void* SSL_renegotiate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[266])(a, b, c, d);
}
void* SSL_renegotiate_pending(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[267])(a, b, c, d);
}
void* SSL_rstate_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[268])(a, b, c, d);
}
void* SSL_rstate_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[269])(a, b, c, d);
}
void* SSL_select_next_proto(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[270])(a, b, c, d);
}
void* SSL_session_reused(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[271])(a, b, c, d);
}
void* SSL_set1_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[272])(a, b, c, d);
}
void* SSL_set1_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[273])(a, b, c, d);
}
void* SSL_set_SSL_CTX(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[274])(a, b, c, d);
}
void* SSL_set_accept_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[275])(a, b, c, d);
}
void* SSL_set_alpn_protos(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[276])(a, b, c, d);
}
void* SSL_set_bio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[277])(a, b, c, d);
}
void* SSL_set_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[278])(a, b, c, d);
}
void* SSL_set_cipher_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[279])(a, b, c, d);
}
void* SSL_set_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[280])(a, b, c, d);
}
void* SSL_set_connect_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[281])(a, b, c, d);
}
void* SSL_set_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[282])(a, b, c, d);
}
void* SSL_set_fd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[283])(a, b, c, d);
}
void* SSL_set_generate_session_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[284])(a, b, c, d);
}
void* SSL_set_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[285])(a, b, c, d);
}
void* SSL_set_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[286])(a, b, c, d);
}
void* SSL_set_max_send_fragment(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[287])(a, b, c, d);
}
void* SSL_set_max_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[288])(a, b, c, d);
}
void* SSL_set_min_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[289])(a, b, c, d);
}
void* SSL_set_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[290])(a, b, c, d);
}
void* SSL_set_msg_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[291])(a, b, c, d);
}
void* SSL_set_msg_callback_arg(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[292])(a, b, c, d);
}
void* SSL_set_mtu(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[293])(a, b, c, d);
}
void* SSL_set_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[294])(a, b, c, d);
}
void* SSL_set_psk_client_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[295])(a, b, c, d);
}
void* SSL_set_psk_server_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[296])(a, b, c, d);
}
void* SSL_set_purpose(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[297])(a, b, c, d);
}
void* SSL_set_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[298])(a, b, c, d);
}
void* SSL_set_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[299])(a, b, c, d);
}
void* SSL_set_reject_peer_renegotiations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[300])(a, b, c, d);
}
void* SSL_set_rfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[301])(a, b, c, d);
}
void* SSL_set_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[302])(a, b, c, d);
}
void* SSL_set_session_id_context(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[303])(a, b, c, d);
}
void* SSL_set_session_secret_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[304])(a, b, c, d);
}
void* SSL_set_session_ticket_ext(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[305])(a, b, c, d);
}
void* SSL_set_session_ticket_ext_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[306])(a, b, c, d);
}
void* SSL_set_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[307])(a, b, c, d);
}
void* SSL_set_srtp_profiles(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[308])(a, b, c, d);
}
void* SSL_set_ssl_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[309])(a, b, c, d);
}
void* SSL_set_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[310])(a, b, c, d);
}
void* SSL_set_tlsext_host_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[311])(a, b, c, d);
}
void* SSL_set_tlsext_use_srtp(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[312])(a, b, c, d);
}
void* SSL_set_tmp_dh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[313])(a, b, c, d);
}
void* SSL_set_tmp_dh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[314])(a, b, c, d);
}
void* SSL_set_tmp_ecdh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[315])(a, b, c, d);
}
void* SSL_set_tmp_ecdh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[316])(a, b, c, d);
}
void* SSL_set_tmp_rsa(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[317])(a, b, c, d);
}
void* SSL_set_tmp_rsa_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[318])(a, b, c, d);
}
void* SSL_set_trust(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[319])(a, b, c, d);
}
void* SSL_set_verify(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[320])(a, b, c, d);
}
void* SSL_set_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[321])(a, b, c, d);
}
void* SSL_set_verify_result(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[322])(a, b, c, d);
}
void* SSL_set_wfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[323])(a, b, c, d);
}
void* SSL_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[324])(a, b, c, d);
}
void* SSL_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[325])(a, b, c, d);
}
void* SSL_state_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[326])(a, b, c, d);
}
void* SSL_state_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[327])(a, b, c, d);
}
void* SSL_total_renegotiations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[328])(a, b, c, d);
}
void* SSL_use_PrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[329])(a, b, c, d);
}
void* SSL_use_PrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[330])(a, b, c, d);
}
void* SSL_use_PrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[331])(a, b, c, d);
}
void* SSL_use_RSAPrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[332])(a, b, c, d);
}
void* SSL_use_RSAPrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[333])(a, b, c, d);
}
void* SSL_use_RSAPrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[334])(a, b, c, d);
}
void* SSL_use_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[335])(a, b, c, d);
}
void* SSL_use_certificate_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[336])(a, b, c, d);
}
void* SSL_use_certificate_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[337])(a, b, c, d);
}
void* SSL_use_psk_identity_hint(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[338])(a, b, c, d);
}
void* SSL_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[339])(a, b, c, d);
}
void* SSL_want(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[340])(a, b, c, d);
}
void* SSL_write(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[341])(a, b, c, d);
}
void* SSLv23_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[342])(a, b, c, d);
}
void* SSLv23_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[343])(a, b, c, d);
}
void* SSLv23_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[344])(a, b, c, d);
}
void* SSLv3_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[345])(a, b, c, d);
}
void* SSLv3_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[346])(a, b, c, d);
}
void* SSLv3_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[347])(a, b, c, d);
}
void* TLS_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[348])(a, b, c, d);
}
void* TLSv1_1_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[349])(a, b, c, d);
}
void* TLSv1_1_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[350])(a, b, c, d);
}
void* TLSv1_1_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[351])(a, b, c, d);
}
void* TLSv1_2_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[352])(a, b, c, d);
}
void* TLSv1_2_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[353])(a, b, c, d);
}
void* TLSv1_2_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[354])(a, b, c, d);
}
void* TLSv1_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[355])(a, b, c, d);
}
void* TLSv1_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[356])(a, b, c, d);
}
void* TLSv1_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[357])(a, b, c, d);
}
void* _Unwind_Backtrace(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[358])(a, b, c, d);
}
void* _Unwind_Complete(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[359])(a, b, c, d);
}
void* _Unwind_DeleteException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[360])(a, b, c, d);
}
void* _Unwind_ForcedUnwind(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[361])(a, b, c, d);
}
void* _Unwind_GetCFA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[362])(a, b, c, d);
}
void* _Unwind_GetDataRelBase(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[363])(a, b, c, d);
}
void* _Unwind_GetLanguageSpecificData(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[364])(a, b, c, d);
}
void* _Unwind_GetRegionStart(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[365])(a, b, c, d);
}
void* _Unwind_GetTextRelBase(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[366])(a, b, c, d);
}
void* _Unwind_RaiseException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[367])(a, b, c, d);
}
void* _Unwind_Resume(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[368])(a, b, c, d);
}
void* _Unwind_Resume_or_Rethrow(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[369])(a, b, c, d);
}
void* _Unwind_VRS_Get(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[370])(a, b, c, d);
}
void* _Unwind_VRS_Pop(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[371])(a, b, c, d);
}
void* _Unwind_VRS_Set(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[372])(a, b, c, d);
}
void* ___Unwind_Backtrace(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[373])(a, b, c, d);
}
void* ___Unwind_ForcedUnwind(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[374])(a, b, c, d);
}
void* ___Unwind_RaiseException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[375])(a, b, c, d);
}
void* ___Unwind_Resume(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[376])(a, b, c, d);
}
void* ___Unwind_Resume_or_Rethrow(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[377])(a, b, c, d);
}
void* __aeabi_unwind_cpp_pr0(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[378])(a, b, c, d);
}
void* __aeabi_unwind_cpp_pr1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[379])(a, b, c, d);
}
void* __aeabi_unwind_cpp_pr2(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[380])(a, b, c, d);
}
void* __gnu_Unwind_Backtrace(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[381])(a, b, c, d);
}
void* __gnu_Unwind_ForcedUnwind(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[382])(a, b, c, d);
}
void* __gnu_Unwind_RaiseException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[383])(a, b, c, d);
}
void* __gnu_Unwind_Restore_VFP(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[384])(a, b, c, d);
}
void* __gnu_Unwind_Restore_VFP_D(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[385])(a, b, c, d);
}
void* __gnu_Unwind_Restore_VFP_D_16_to_31(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[386])(a, b, c, d);
}
void* __gnu_Unwind_Restore_WMMXC(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[387])(a, b, c, d);
}
void* __gnu_Unwind_Restore_WMMXD(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[388])(a, b, c, d);
}
void* __gnu_Unwind_Resume(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[389])(a, b, c, d);
}
void* __gnu_Unwind_Resume_or_Rethrow(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[390])(a, b, c, d);
}
void* __gnu_Unwind_Save_VFP(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[391])(a, b, c, d);
}
void* __gnu_Unwind_Save_VFP_D(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[392])(a, b, c, d);
}
void* __gnu_Unwind_Save_VFP_D_16_to_31(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[393])(a, b, c, d);
}
void* __gnu_Unwind_Save_WMMXC(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[394])(a, b, c, d);
}
void* __gnu_Unwind_Save_WMMXD(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[395])(a, b, c, d);
}
void* __gnu_unwind_execute(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[396])(a, b, c, d);
}
void* __gnu_unwind_frame(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[397])(a, b, c, d);
}
void* __restore_core_regs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[398])(a, b, c, d);
}
void* d2i_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[399])(a, b, c, d);
}
void* i2d_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[400])(a, b, c, d);
}
void* pitem_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[401])(a, b, c, d);
}
void* pitem_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[402])(a, b, c, d);
}
void* pqueue_find(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[403])(a, b, c, d);
}
void* pqueue_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[404])(a, b, c, d);
}
void* pqueue_insert(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[405])(a, b, c, d);
}
void* pqueue_iterator(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[406])(a, b, c, d);
}
void* pqueue_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[407])(a, b, c, d);
}
void* pqueue_next(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[408])(a, b, c, d);
}
void* pqueue_peek(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[409])(a, b, c, d);
}
void* pqueue_pop(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[410])(a, b, c, d);
}
void* pqueue_size(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[411])(a, b, c, d);
}
void* restore_core_regs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[412])(a, b, c, d);
}
void* cleanup(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[413])(a, b, c, d);
}
void* log_binary(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[414])(a, b, c, d);
}
void* setup(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[415])(a, b, c, d);
}
void* __atexit_handler_wrapper(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[416])(a, b, c, d);
}
void* __on_dlclose(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[417])(a, b, c, d);
}
void* atexit(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[418])(a, b, c, d);
}
void* BIO_f_ssl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[419])(a, b, c, d);
}
void* BIO_new_buffer_ssl_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[420])(a, b, c, d);
}
void* BIO_new_ssl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[421])(a, b, c, d);
}
void* BIO_new_ssl_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[422])(a, b, c, d);
}
void* BIO_ssl_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[423])(a, b, c, d);
}
void* DTLS_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[424])(a, b, c, d);
}
void* DTLS_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[425])(a, b, c, d);
}
void* DTLS_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[426])(a, b, c, d);
}
void* DTLSv1_2_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[427])(a, b, c, d);
}
void* DTLSv1_2_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[428])(a, b, c, d);
}
void* DTLSv1_2_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[429])(a, b, c, d);
}
void* DTLSv1_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[430])(a, b, c, d);
}
void* DTLSv1_get_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[431])(a, b, c, d);
}
void* DTLSv1_handle_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[432])(a, b, c, d);
}
void* DTLSv1_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[433])(a, b, c, d);
}
void* DTLSv1_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[434])(a, b, c, d);
}
void* PEM_read_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[435])(a, b, c, d);
}
void* PEM_read_bio_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[436])(a, b, c, d);
}
void* PEM_write_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[437])(a, b, c, d);
}
void* PEM_write_bio_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[438])(a, b, c, d);
}
void* SSL_CIPHER_description(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[439])(a, b, c, d);
}
void* SSL_CIPHER_get_bits(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[440])(a, b, c, d);
}
void* SSL_CIPHER_get_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[441])(a, b, c, d);
}
void* SSL_CIPHER_get_kx_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[442])(a, b, c, d);
}
void* SSL_CIPHER_get_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[443])(a, b, c, d);
}
void* SSL_CIPHER_get_rfc_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[444])(a, b, c, d);
}
void* SSL_CIPHER_get_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[445])(a, b, c, d);
}
void* SSL_CIPHER_has_MD5_HMAC(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[446])(a, b, c, d);
}
void* SSL_CIPHER_is_AES(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[447])(a, b, c, d);
}
void* SSL_CIPHER_is_AESGCM(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[448])(a, b, c, d);
}
void* SSL_CIPHER_is_CHACHA20POLY1305(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[449])(a, b, c, d);
}
void* SSL_COMP_add_compression_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[450])(a, b, c, d);
}
void* SSL_COMP_get_compression_methods(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[451])(a, b, c, d);
}
void* SSL_COMP_get_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[452])(a, b, c, d);
}
void* SSL_CTX_add_client_CA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[453])(a, b, c, d);
}
void* SSL_CTX_add_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[454])(a, b, c, d);
}
void* SSL_CTX_check_private_key(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[455])(a, b, c, d);
}
void* SSL_CTX_clear_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[456])(a, b, c, d);
}
void* SSL_CTX_clear_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[457])(a, b, c, d);
}
void* SSL_CTX_ctrl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[458])(a, b, c, d);
}
void* SSL_CTX_enable_ocsp_stapling(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[459])(a, b, c, d);
}
void* SSL_CTX_enable_signed_cert_timestamps(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[460])(a, b, c, d);
}
void* SSL_CTX_enable_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[461])(a, b, c, d);
}
void* SSL_CTX_flush_sessions(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[462])(a, b, c, d);
}
void* SSL_CTX_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[463])(a, b, c, d);
}
void* SSL_CTX_get0_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[464])(a, b, c, d);
}
void* SSL_CTX_get0_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[465])(a, b, c, d);
}
void* SSL_CTX_get0_privatekey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[466])(a, b, c, d);
}
void* SSL_CTX_get_cert_store(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[467])(a, b, c, d);
}
void* SSL_CTX_get_channel_id_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[468])(a, b, c, d);
}
void* SSL_CTX_get_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[469])(a, b, c, d);
}
void* SSL_CTX_get_client_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[470])(a, b, c, d);
}
void* SSL_CTX_get_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[471])(a, b, c, d);
}
void* SSL_CTX_get_ex_new_index(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[472])(a, b, c, d);
}
void* SSL_CTX_get_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[473])(a, b, c, d);
}
void* SSL_CTX_get_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[474])(a, b, c, d);
}
void* SSL_CTX_get_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[475])(a, b, c, d);
}
void* SSL_CTX_get_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[476])(a, b, c, d);
}
void* SSL_CTX_get_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[477])(a, b, c, d);
}
void* SSL_CTX_get_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[478])(a, b, c, d);
}
void* SSL_CTX_get_session_cache_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[479])(a, b, c, d);
}
void* SSL_CTX_get_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[480])(a, b, c, d);
}
void* SSL_CTX_get_verify_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[481])(a, b, c, d);
}
void* SSL_CTX_get_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[482])(a, b, c, d);
}
void* SSL_CTX_get_verify_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[483])(a, b, c, d);
}
void* SSL_CTX_load_verify_locations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[484])(a, b, c, d);
}
void* SSL_CTX_need_tmp_RSA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[485])(a, b, c, d);
}
void* SSL_CTX_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[486])(a, b, c, d);
}
void* SSL_CTX_remove_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[487])(a, b, c, d);
}
void* SSL_CTX_sess_accept(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[488])(a, b, c, d);
}
void* SSL_CTX_sess_accept_good(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[489])(a, b, c, d);
}
void* SSL_CTX_sess_accept_renegotiate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[490])(a, b, c, d);
}
void* SSL_CTX_sess_cache_full(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[491])(a, b, c, d);
}
void* SSL_CTX_sess_cb_hits(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[492])(a, b, c, d);
}
void* SSL_CTX_sess_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[493])(a, b, c, d);
}
void* SSL_CTX_sess_connect_good(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[494])(a, b, c, d);
}
void* SSL_CTX_sess_connect_renegotiate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[495])(a, b, c, d);
}
void* SSL_CTX_sess_get_cache_size(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[496])(a, b, c, d);
}
void* SSL_CTX_sess_get_get_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[497])(a, b, c, d);
}
void* SSL_CTX_sess_get_new_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[498])(a, b, c, d);
}
void* SSL_CTX_sess_get_remove_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[499])(a, b, c, d);
}
void* SSL_CTX_sess_hits(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[500])(a, b, c, d);
}
void* SSL_CTX_sess_misses(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[501])(a, b, c, d);
}
void* SSL_CTX_sess_number(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[502])(a, b, c, d);
}
void* SSL_CTX_sess_set_cache_size(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[503])(a, b, c, d);
}
void* SSL_CTX_sess_set_get_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[504])(a, b, c, d);
}
void* SSL_CTX_sess_set_new_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[505])(a, b, c, d);
}
void* SSL_CTX_sess_set_remove_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[506])(a, b, c, d);
}
void* SSL_CTX_sess_timeouts(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[507])(a, b, c, d);
}
void* SSL_CTX_sessions(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[508])(a, b, c, d);
}
void* SSL_CTX_set1_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[509])(a, b, c, d);
}
void* SSL_CTX_set1_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[510])(a, b, c, d);
}
void* SSL_CTX_set_alpn_protos(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[511])(a, b, c, d);
}
void* SSL_CTX_set_alpn_select_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[512])(a, b, c, d);
}
void* SSL_CTX_set_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[513])(a, b, c, d);
}
void* SSL_CTX_set_cert_store(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[514])(a, b, c, d);
}
void* SSL_CTX_set_cert_verify_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[515])(a, b, c, d);
}
void* SSL_CTX_set_channel_id_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[516])(a, b, c, d);
}
void* SSL_CTX_set_cipher_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[517])(a, b, c, d);
}
void* SSL_CTX_set_cipher_list_tls11(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[518])(a, b, c, d);
}
void* SSL_CTX_set_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[519])(a, b, c, d);
}
void* SSL_CTX_set_client_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[520])(a, b, c, d);
}
void* SSL_CTX_set_default_passwd_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[521])(a, b, c, d);
}
void* SSL_CTX_set_default_passwd_cb_userdata(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[522])(a, b, c, d);
}
void* SSL_CTX_set_default_verify_paths(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[523])(a, b, c, d);
}
void* SSL_CTX_set_dos_protection_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[524])(a, b, c, d);
}
void* SSL_CTX_set_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[525])(a, b, c, d);
}
void* SSL_CTX_set_generate_session_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[526])(a, b, c, d);
}
void* SSL_CTX_set_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[527])(a, b, c, d);
}
void* SSL_CTX_set_keylog_bio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[528])(a, b, c, d);
}
void* SSL_CTX_set_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[529])(a, b, c, d);
}
void* SSL_CTX_set_max_send_fragment(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[530])(a, b, c, d);
}
void* SSL_CTX_set_max_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[531])(a, b, c, d);
}
void* SSL_CTX_set_min_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[532])(a, b, c, d);
}
void* SSL_CTX_set_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[533])(a, b, c, d);
}
void* SSL_CTX_set_msg_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[534])(a, b, c, d);
}
void* SSL_CTX_set_msg_callback_arg(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[535])(a, b, c, d);
}
void* SSL_CTX_set_next_proto_select_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[536])(a, b, c, d);
}
void* SSL_CTX_set_next_protos_advertised_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[537])(a, b, c, d);
}
void* SSL_CTX_set_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[538])(a, b, c, d);
}
void* SSL_CTX_set_psk_client_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[539])(a, b, c, d);
}
void* SSL_CTX_set_psk_server_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[540])(a, b, c, d);
}
void* SSL_CTX_set_purpose(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[541])(a, b, c, d);
}
void* SSL_CTX_set_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[542])(a, b, c, d);
}
void* SSL_CTX_set_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[543])(a, b, c, d);
}
void* SSL_CTX_set_session_cache_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[544])(a, b, c, d);
}
void* SSL_CTX_set_session_id_context(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[545])(a, b, c, d);
}
void* SSL_CTX_set_srtp_profiles(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[546])(a, b, c, d);
}
void* SSL_CTX_set_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[547])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_servername_arg(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[548])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_servername_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[549])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_ticket_key_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[550])(a, b, c, d);
}
void* SSL_CTX_set_tlsext_use_srtp(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[551])(a, b, c, d);
}
void* SSL_CTX_set_tmp_dh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[552])(a, b, c, d);
}
void* SSL_CTX_set_tmp_dh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[553])(a, b, c, d);
}
void* SSL_CTX_set_tmp_ecdh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[554])(a, b, c, d);
}
void* SSL_CTX_set_tmp_ecdh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[555])(a, b, c, d);
}
void* SSL_CTX_set_tmp_rsa(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[556])(a, b, c, d);
}
void* SSL_CTX_set_tmp_rsa_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[557])(a, b, c, d);
}
void* SSL_CTX_set_trust(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[558])(a, b, c, d);
}
void* SSL_CTX_set_verify(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[559])(a, b, c, d);
}
void* SSL_CTX_set_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[560])(a, b, c, d);
}
void* SSL_CTX_use_PrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[561])(a, b, c, d);
}
void* SSL_CTX_use_PrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[562])(a, b, c, d);
}
void* SSL_CTX_use_PrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[563])(a, b, c, d);
}
void* SSL_CTX_use_RSAPrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[564])(a, b, c, d);
}
void* SSL_CTX_use_RSAPrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[565])(a, b, c, d);
}
void* SSL_CTX_use_RSAPrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[566])(a, b, c, d);
}
void* SSL_CTX_use_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[567])(a, b, c, d);
}
void* SSL_CTX_use_certificate_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[568])(a, b, c, d);
}
void* SSL_CTX_use_certificate_chain_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[569])(a, b, c, d);
}
void* SSL_CTX_use_certificate_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[570])(a, b, c, d);
}
void* SSL_CTX_use_psk_identity_hint(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[571])(a, b, c, d);
}
void* SSL_SESSION_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[572])(a, b, c, d);
}
void* SSL_SESSION_get0_peer(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[573])(a, b, c, d);
}
void* SSL_SESSION_get_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[574])(a, b, c, d);
}
void* SSL_SESSION_get_ex_new_index(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[575])(a, b, c, d);
}
void* SSL_SESSION_get_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[576])(a, b, c, d);
}
void* SSL_SESSION_get_time(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[577])(a, b, c, d);
}
void* SSL_SESSION_get_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[578])(a, b, c, d);
}
void* SSL_SESSION_get_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[579])(a, b, c, d);
}
void* SSL_SESSION_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[580])(a, b, c, d);
}
void* SSL_SESSION_print(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[581])(a, b, c, d);
}
void* SSL_SESSION_print_fp(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[582])(a, b, c, d);
}
void* SSL_SESSION_set1_id_context(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[583])(a, b, c, d);
}
void* SSL_SESSION_set_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[584])(a, b, c, d);
}
void* SSL_SESSION_set_time(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[585])(a, b, c, d);
}
void* SSL_SESSION_set_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[586])(a, b, c, d);
}
void* SSL_SESSION_to_bytes(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[587])(a, b, c, d);
}
void* SSL_SESSION_to_bytes_for_ticket(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[588])(a, b, c, d);
}
void* SSL_SESSION_up_ref(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[589])(a, b, c, d);
}
void* SSL_accept(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[590])(a, b, c, d);
}
void* SSL_add_client_CA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[591])(a, b, c, d);
}
void* SSL_add_dir_cert_subjects_to_stack(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[592])(a, b, c, d);
}
void* SSL_add_file_cert_subjects_to_stack(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[593])(a, b, c, d);
}
void* SSL_alert_desc_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[594])(a, b, c, d);
}
void* SSL_alert_desc_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[595])(a, b, c, d);
}
void* SSL_alert_type_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[596])(a, b, c, d);
}
void* SSL_alert_type_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[597])(a, b, c, d);
}
void* SSL_cache_hit(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[598])(a, b, c, d);
}
void* SSL_certs_clear(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[599])(a, b, c, d);
}
void* SSL_check_private_key(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[600])(a, b, c, d);
}
void* SSL_clear(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[601])(a, b, c, d);
}
void* SSL_clear_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[602])(a, b, c, d);
}
void* SSL_clear_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[603])(a, b, c, d);
}
void* SSL_connect(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[604])(a, b, c, d);
}
void* SSL_ctrl(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[605])(a, b, c, d);
}
void* SSL_cutthrough_complete(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[606])(a, b, c, d);
}
void* SSL_do_handshake(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[607])(a, b, c, d);
}
void* SSL_dup_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[608])(a, b, c, d);
}
void* SSL_early_callback_ctx_extension_get(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[609])(a, b, c, d);
}
void* SSL_enable_fastradio_padding(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[610])(a, b, c, d);
}
void* SSL_enable_ocsp_stapling(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[611])(a, b, c, d);
}
void* SSL_enable_signed_cert_timestamps(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[612])(a, b, c, d);
}
void* SSL_enable_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[613])(a, b, c, d);
}
void* SSL_export_keying_material(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[614])(a, b, c, d);
}
void* SSL_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[615])(a, b, c, d);
}
void* SSL_get0_alpn_selected(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[616])(a, b, c, d);
}
void* SSL_get0_next_proto_negotiated(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[617])(a, b, c, d);
}
void* SSL_get0_ocsp_response(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[618])(a, b, c, d);
}
void* SSL_get0_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[619])(a, b, c, d);
}
void* SSL_get0_signed_cert_timestamp_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[620])(a, b, c, d);
}
void* SSL_get1_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[621])(a, b, c, d);
}
void* SSL_get_SSL_CTX(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[622])(a, b, c, d);
}
void* SSL_get_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[623])(a, b, c, d);
}
void* SSL_get_cipher_by_value(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[624])(a, b, c, d);
}
void* SSL_get_cipher_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[625])(a, b, c, d);
}
void* SSL_get_ciphers(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[626])(a, b, c, d);
}
void* SSL_get_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[627])(a, b, c, d);
}
void* SSL_get_current_cipher(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[628])(a, b, c, d);
}
void* SSL_get_current_compression(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[629])(a, b, c, d);
}
void* SSL_get_current_expansion(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[630])(a, b, c, d);
}
void* SSL_get_default_timeout(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[631])(a, b, c, d);
}
void* SSL_get_error(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[632])(a, b, c, d);
}
void* SSL_get_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[633])(a, b, c, d);
}
void* SSL_get_ex_data_X509_STORE_CTX_idx(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[634])(a, b, c, d);
}
void* SSL_get_ex_new_index(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[635])(a, b, c, d);
}
void* SSL_get_fd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[636])(a, b, c, d);
}
void* SSL_get_finished(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[637])(a, b, c, d);
}
void* SSL_get_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[638])(a, b, c, d);
}
void* SSL_get_key_block_length(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[639])(a, b, c, d);
}
void* SSL_get_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[640])(a, b, c, d);
}
void* SSL_get_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[641])(a, b, c, d);
}
void* SSL_get_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[642])(a, b, c, d);
}
void* SSL_get_peer_cert_chain(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[643])(a, b, c, d);
}
void* SSL_get_peer_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[644])(a, b, c, d);
}
void* SSL_get_peer_finished(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[645])(a, b, c, d);
}
void* SSL_get_privatekey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[646])(a, b, c, d);
}
void* SSL_get_psk_identity(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[647])(a, b, c, d);
}
void* SSL_get_psk_identity_hint(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[648])(a, b, c, d);
}
void* SSL_get_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[649])(a, b, c, d);
}
void* SSL_get_rbio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[650])(a, b, c, d);
}
void* SSL_get_rc4_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[651])(a, b, c, d);
}
void* SSL_get_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[652])(a, b, c, d);
}
void* SSL_get_rfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[653])(a, b, c, d);
}
void* SSL_get_secure_renegotiation_support(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[654])(a, b, c, d);
}
void* SSL_get_selected_srtp_profile(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[655])(a, b, c, d);
}
void* SSL_get_servername(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[656])(a, b, c, d);
}
void* SSL_get_servername_type(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[657])(a, b, c, d);
}
void* SSL_get_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[658])(a, b, c, d);
}
void* SSL_get_shared_sigalgs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[659])(a, b, c, d);
}
void* SSL_get_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[660])(a, b, c, d);
}
void* SSL_get_sigalgs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[661])(a, b, c, d);
}
void* SSL_get_srtp_profiles(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[662])(a, b, c, d);
}
void* SSL_get_structure_sizes(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[663])(a, b, c, d);
}
void* SSL_get_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[664])(a, b, c, d);
}
void* SSL_get_tls_unique(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[665])(a, b, c, d);
}
void* SSL_get_verify_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[666])(a, b, c, d);
}
void* SSL_get_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[667])(a, b, c, d);
}
void* SSL_get_verify_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[668])(a, b, c, d);
}
void* SSL_get_verify_result(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[669])(a, b, c, d);
}
void* SSL_get_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[670])(a, b, c, d);
}
void* SSL_get_wbio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[671])(a, b, c, d);
}
void* SSL_get_wfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[672])(a, b, c, d);
}
void* SSL_has_matching_session_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[673])(a, b, c, d);
}
void* SSL_in_false_start(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[674])(a, b, c, d);
}
void* SSL_is_server(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[675])(a, b, c, d);
}
void* SSL_library_init(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[676])(a, b, c, d);
}
void* SSL_load_client_CA_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[677])(a, b, c, d);
}
void* SSL_load_error_strings(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[678])(a, b, c, d);
}
void* SSL_magic_pending_session_ptr(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[679])(a, b, c, d);
}
void* SSL_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[680])(a, b, c, d);
}
void* SSL_num_renegotiations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[681])(a, b, c, d);
}
void* SSL_peek(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[682])(a, b, c, d);
}
void* SSL_pending(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[683])(a, b, c, d);
}
void* SSL_read(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[684])(a, b, c, d);
}
void* SSL_renegotiate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[685])(a, b, c, d);
}
void* SSL_renegotiate_pending(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[686])(a, b, c, d);
}
void* SSL_rstate_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[687])(a, b, c, d);
}
void* SSL_rstate_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[688])(a, b, c, d);
}
void* SSL_select_next_proto(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[689])(a, b, c, d);
}
void* SSL_session_reused(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[690])(a, b, c, d);
}
void* SSL_set1_param(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[691])(a, b, c, d);
}
void* SSL_set1_tls_channel_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[692])(a, b, c, d);
}
void* SSL_set_SSL_CTX(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[693])(a, b, c, d);
}
void* SSL_set_accept_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[694])(a, b, c, d);
}
void* SSL_set_alpn_protos(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[695])(a, b, c, d);
}
void* SSL_set_bio(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[696])(a, b, c, d);
}
void* SSL_set_cert_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[697])(a, b, c, d);
}
void* SSL_set_cipher_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[698])(a, b, c, d);
}
void* SSL_set_client_CA_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[699])(a, b, c, d);
}
void* SSL_set_connect_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[700])(a, b, c, d);
}
void* SSL_set_ex_data(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[701])(a, b, c, d);
}
void* SSL_set_fd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[702])(a, b, c, d);
}
void* SSL_set_generate_session_id(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[703])(a, b, c, d);
}
void* SSL_set_info_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[704])(a, b, c, d);
}
void* SSL_set_max_cert_list(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[705])(a, b, c, d);
}
void* SSL_set_max_send_fragment(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[706])(a, b, c, d);
}
void* SSL_set_max_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[707])(a, b, c, d);
}
void* SSL_set_min_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[708])(a, b, c, d);
}
void* SSL_set_mode(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[709])(a, b, c, d);
}
void* SSL_set_msg_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[710])(a, b, c, d);
}
void* SSL_set_msg_callback_arg(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[711])(a, b, c, d);
}
void* SSL_set_mtu(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[712])(a, b, c, d);
}
void* SSL_set_options(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[713])(a, b, c, d);
}
void* SSL_set_psk_client_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[714])(a, b, c, d);
}
void* SSL_set_psk_server_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[715])(a, b, c, d);
}
void* SSL_set_purpose(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[716])(a, b, c, d);
}
void* SSL_set_quiet_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[717])(a, b, c, d);
}
void* SSL_set_read_ahead(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[718])(a, b, c, d);
}
void* SSL_set_reject_peer_renegotiations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[719])(a, b, c, d);
}
void* SSL_set_rfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[720])(a, b, c, d);
}
void* SSL_set_session(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[721])(a, b, c, d);
}
void* SSL_set_session_id_context(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[722])(a, b, c, d);
}
void* SSL_set_session_secret_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[723])(a, b, c, d);
}
void* SSL_set_session_ticket_ext(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[724])(a, b, c, d);
}
void* SSL_set_session_ticket_ext_cb(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[725])(a, b, c, d);
}
void* SSL_set_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[726])(a, b, c, d);
}
void* SSL_set_srtp_profiles(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[727])(a, b, c, d);
}
void* SSL_set_ssl_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[728])(a, b, c, d);
}
void* SSL_set_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[729])(a, b, c, d);
}
void* SSL_set_tlsext_host_name(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[730])(a, b, c, d);
}
void* SSL_set_tlsext_use_srtp(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[731])(a, b, c, d);
}
void* SSL_set_tmp_dh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[732])(a, b, c, d);
}
void* SSL_set_tmp_dh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[733])(a, b, c, d);
}
void* SSL_set_tmp_ecdh(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[734])(a, b, c, d);
}
void* SSL_set_tmp_ecdh_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[735])(a, b, c, d);
}
void* SSL_set_tmp_rsa(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[736])(a, b, c, d);
}
void* SSL_set_tmp_rsa_callback(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[737])(a, b, c, d);
}
void* SSL_set_trust(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[738])(a, b, c, d);
}
void* SSL_set_verify(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[739])(a, b, c, d);
}
void* SSL_set_verify_depth(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[740])(a, b, c, d);
}
void* SSL_set_verify_result(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[741])(a, b, c, d);
}
void* SSL_set_wfd(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[742])(a, b, c, d);
}
void* SSL_shutdown(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[743])(a, b, c, d);
}
void* SSL_state(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[744])(a, b, c, d);
}
void* SSL_state_string(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[745])(a, b, c, d);
}
void* SSL_state_string_long(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[746])(a, b, c, d);
}
void* SSL_total_renegotiations(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[747])(a, b, c, d);
}
void* SSL_use_PrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[748])(a, b, c, d);
}
void* SSL_use_PrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[749])(a, b, c, d);
}
void* SSL_use_PrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[750])(a, b, c, d);
}
void* SSL_use_RSAPrivateKey(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[751])(a, b, c, d);
}
void* SSL_use_RSAPrivateKey_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[752])(a, b, c, d);
}
void* SSL_use_RSAPrivateKey_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[753])(a, b, c, d);
}
void* SSL_use_certificate(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[754])(a, b, c, d);
}
void* SSL_use_certificate_ASN1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[755])(a, b, c, d);
}
void* SSL_use_certificate_file(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[756])(a, b, c, d);
}
void* SSL_use_psk_identity_hint(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[757])(a, b, c, d);
}
void* SSL_version(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[758])(a, b, c, d);
}
void* SSL_want(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[759])(a, b, c, d);
}
void* SSL_write(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[760])(a, b, c, d);
}
void* SSLv23_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[761])(a, b, c, d);
}
void* SSLv23_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[762])(a, b, c, d);
}
void* SSLv23_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[763])(a, b, c, d);
}
void* SSLv3_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[764])(a, b, c, d);
}
void* SSLv3_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[765])(a, b, c, d);
}
void* SSLv3_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[766])(a, b, c, d);
}
void* TLS_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[767])(a, b, c, d);
}
void* TLSv1_1_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[768])(a, b, c, d);
}
void* TLSv1_1_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[769])(a, b, c, d);
}
void* TLSv1_1_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[770])(a, b, c, d);
}
void* TLSv1_2_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[771])(a, b, c, d);
}
void* TLSv1_2_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[772])(a, b, c, d);
}
void* TLSv1_2_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[773])(a, b, c, d);
}
void* TLSv1_client_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[774])(a, b, c, d);
}
void* TLSv1_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[775])(a, b, c, d);
}
void* TLSv1_server_method(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[776])(a, b, c, d);
}
void* _Unwind_Backtrace(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[777])(a, b, c, d);
}
void* _Unwind_Complete(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[778])(a, b, c, d);
}
void* _Unwind_DeleteException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[779])(a, b, c, d);
}
void* _Unwind_ForcedUnwind(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[780])(a, b, c, d);
}
void* _Unwind_GetCFA(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[781])(a, b, c, d);
}
void* _Unwind_GetDataRelBase(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[782])(a, b, c, d);
}
void* _Unwind_GetLanguageSpecificData(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[783])(a, b, c, d);
}
void* _Unwind_GetRegionStart(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[784])(a, b, c, d);
}
void* _Unwind_GetTextRelBase(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[785])(a, b, c, d);
}
void* _Unwind_RaiseException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[786])(a, b, c, d);
}
void* _Unwind_Resume(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[787])(a, b, c, d);
}
void* _Unwind_Resume_or_Rethrow(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[788])(a, b, c, d);
}
void* _Unwind_VRS_Get(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[789])(a, b, c, d);
}
void* _Unwind_VRS_Pop(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[790])(a, b, c, d);
}
void* _Unwind_VRS_Set(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[791])(a, b, c, d);
}
void* ___Unwind_Backtrace(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[792])(a, b, c, d);
}
void* ___Unwind_ForcedUnwind(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[793])(a, b, c, d);
}
void* ___Unwind_RaiseException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[794])(a, b, c, d);
}
void* ___Unwind_Resume(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[795])(a, b, c, d);
}
void* ___Unwind_Resume_or_Rethrow(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[796])(a, b, c, d);
}
void* __aeabi_unwind_cpp_pr0(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[797])(a, b, c, d);
}
void* __aeabi_unwind_cpp_pr1(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[798])(a, b, c, d);
}
void* __aeabi_unwind_cpp_pr2(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[799])(a, b, c, d);
}
void* __gnu_Unwind_Backtrace(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[800])(a, b, c, d);
}
void* __gnu_Unwind_ForcedUnwind(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[801])(a, b, c, d);
}
void* __gnu_Unwind_RaiseException(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[802])(a, b, c, d);
}
void* __gnu_Unwind_Restore_VFP(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[803])(a, b, c, d);
}
void* __gnu_Unwind_Restore_VFP_D(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[804])(a, b, c, d);
}
void* __gnu_Unwind_Restore_VFP_D_16_to_31(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[805])(a, b, c, d);
}
void* __gnu_Unwind_Restore_WMMXC(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[806])(a, b, c, d);
}
void* __gnu_Unwind_Restore_WMMXD(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[807])(a, b, c, d);
}
void* __gnu_Unwind_Resume(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[808])(a, b, c, d);
}
void* __gnu_Unwind_Resume_or_Rethrow(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[809])(a, b, c, d);
}
void* __gnu_Unwind_Save_VFP(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[810])(a, b, c, d);
}
void* __gnu_Unwind_Save_VFP_D(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[811])(a, b, c, d);
}
void* __gnu_Unwind_Save_VFP_D_16_to_31(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[812])(a, b, c, d);
}
void* __gnu_Unwind_Save_WMMXC(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[813])(a, b, c, d);
}
void* __gnu_Unwind_Save_WMMXD(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[814])(a, b, c, d);
}
void* __gnu_unwind_execute(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[815])(a, b, c, d);
}
void* __gnu_unwind_frame(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[816])(a, b, c, d);
}
void* __restore_core_regs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[817])(a, b, c, d);
}
void* d2i_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[818])(a, b, c, d);
}
void* i2d_SSL_SESSION(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[819])(a, b, c, d);
}
void* pitem_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[820])(a, b, c, d);
}
void* pitem_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[821])(a, b, c, d);
}
void* pqueue_find(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[822])(a, b, c, d);
}
void* pqueue_free(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[823])(a, b, c, d);
}
void* pqueue_insert(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[824])(a, b, c, d);
}
void* pqueue_iterator(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[825])(a, b, c, d);
}
void* pqueue_new(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[826])(a, b, c, d);
}
void* pqueue_next(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[827])(a, b, c, d);
}
void* pqueue_peek(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[828])(a, b, c, d);
}
void* pqueue_pop(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[829])(a, b, c, d);
}
void* pqueue_size(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[830])(a, b, c, d);
}
void* restore_core_regs(void* a, void* b, void* c, void* d) {
    return ((void* (*) (void*, void*, void*, void*)) func_addr[831])(a, b, c, d);
}
