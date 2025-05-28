// Copyright (c) 2020 Cesanta Software Limited
// All rights reserved

#include <signal.h>
#include <stddef.h> 
#include <string.h> 
#include <stdio.h>  
#include <stdlib.h> 
#include "mongoose.h"

static int s_debug_level = MG_LL_INFO;
static const char *s_root_dir = ".";
static const char *s_addr1 = "http://0.0.0.0:8000";
#ifndef MG_TLS_DISABLED
static const char *s_addr2 = "https://0.0.0.0:8443"; // Only if TLS is not disabled
#endif
static const char *s_enable_hexdump = "no";
static const char *s_ssi_pattern = "#.html";
static const char *s_upload_dir = NULL;  // File uploads disabled by default

// Path to your balcon.exe and the batch file
static const char *s_balcon_script_path = "C:\\balcon\\run_balcon.bat";


// Self signed certificates, only if TLS is not disabled
#ifndef MG_TLS_DISABLED
#ifdef TLS_TWOWAY // This is a custom define from the original example, keep if relevant for your TLS setup
static const char *s_tls_ca =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBFTCBvAIJAMNTFtpfcq8NMAoGCCqGSM49BAMCMBMxETAPBgNVBAMMCE1vbmdv\n"
    "b3NlMB4XDTI0MDUwNzE0MzczNloXDTM0MDUwNTE0MzczNlowEzERMA8GA1UEAwwI\n"
    "TW9uZ29vc2UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASuP+86T/rOWnGpEVhl\n"
    "fxYZ+pjMbCmDZ+vdnP0rjoxudwRMRQCv5slRlDK7Lxue761sdvqxWr0Ma6TFGTNg\n"
    "epsRMAoGCCqGSM49BAMCA0gAMEUCIQCwb2CxuAKm51s81S6BIoy1IcandXSohnqs\n"
    "us64BAA7QgIgGGtUrpkgFSS0oPBlCUG6YPHFVw42vTfpTC0ySwAS0M4=\n"
    "-----END CERTIFICATE-----\n";
#endif
static const char *s_tls_cert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBMTCB2aADAgECAgkAluqkgeuV/zUwCgYIKoZIzj0EAwIwEzERMA8GA1UEAwwI\n"
    "TW9uZ29vc2UwHhcNMjQwNTA3MTQzNzM2WhcNMzQwNTA1MTQzNzM2WjARMQ8wDQYD\n"
    "VQQDDAZzZXJ2ZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASo3oEiG+BuTt5y\n"
    "ZRyfwNr0C+SP+4M0RG2pYkb2v+ivbpfi72NHkmXiF/kbHXtgmSrn/PeTqiA8M+mg\n"
    "BhYjDX+zoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDRwAw\n"
    "RAIgTXW9MITQSwzqbNTxUUdt9DcB+8pPUTbWZpiXcA26GMYCIBiYw+DSFMLHmkHF\n"
    "+5U3NXW3gVCLN9ntD5DAx8LTG8sB\n"
    "-----END CERTIFICATE-----\n";

static const char *s_tls_key =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIAVdo8UAScxG7jiuNY2UZESNX/KPH8qJ0u0gOMMsAzYWoAoGCCqGSM49\n"
    "AwEHoUQDQgAEqN6BIhvgbk7ecmUcn8Da9Avkj/uDNERtqWJG9r/or26X4u9jR5Jl\n"
    "4hf5Gx17YJkq5/z3k6ogPDPpoAYWIw1/sw==\n"
    "-----END EC PRIVATE KEY-----\n";
#endif // MG_TLS_DISABLED

// Handle interrupts, like Ctrl-C
static int s_signo;
static void signal_handler(int signo) {
  s_signo = signo;
}

// Event handler for the listening connection.
static void cb(struct mg_connection *c, int ev, void *ev_data) {
#ifndef MG_TLS_DISABLED
  if (ev == MG_EV_ACCEPT && c->is_tls) {
    struct mg_tls_opts opts;
    memset(&opts, 0, sizeof(opts));
#ifdef TLS_TWOWAY 
    opts.ca = mg_str(s_tls_ca); 
#endif
    opts.cert = mg_str(s_tls_cert);
    opts.key = mg_str(s_tls_key);
    mg_tls_init(c, &opts); // Corrected: removed the if != 0 check
  } else 
#endif // MG_TLS_DISABLED
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    MG_INFO(("%.*s %.*s", (int) hm->method.len, hm->method.buf, (int) hm->uri.len, hm->uri.buf));

    // Handle /balcon endpoint for TTS
    if (mg_match(hm->uri, mg_str("/balcon"), NULL)) {
      char balcon_args[4096] = ""; // Buffer for balcon arguments
      char command_to_run[4200];    // Buffer for the system command

      // Try to get 'args' from query string (for GET requests)
      mg_http_get_var(&hm->query, "args", balcon_args, sizeof(balcon_args) -1);
      balcon_args[sizeof(balcon_args)-1] = '\0'; // Ensure null termination

      // If args is still empty and it's a POST request, try to get 'args' from POST body
      if (balcon_args[0] == '\0' && mg_match(hm->method, mg_str("POST"), NULL)) {
        char body_param_buffer[4096]; 
        if (hm->body.len < sizeof(body_param_buffer) -1) { // Check if body fits
            strncpy(body_param_buffer, hm->body.buf, hm->body.len);
            body_param_buffer[hm->body.len] = '\0';

            char* args_value_start = strstr(body_param_buffer, "args=");
            if (args_value_start) {
                args_value_start += 5; // Move past "args="
                char* args_value_end = strchr(args_value_start, '&'); // Find end if other params exist
                if (args_value_end) {
                    size_t len_to_copy = args_value_end - args_value_start;
                    if (len_to_copy < sizeof(balcon_args)) { // Check against balcon_args buffer
                        strncpy(balcon_args, args_value_start, len_to_copy);
                        balcon_args[len_to_copy] = '\0';
                    } else {
                        strncpy(balcon_args, args_value_start, sizeof(balcon_args) - 1);
                        balcon_args[sizeof(balcon_args)-1] = '\0';
                    }
                } else {
                    strncpy(balcon_args, args_value_start, sizeof(balcon_args) - 1);
                    balcon_args[sizeof(balcon_args)-1] = '\0';
                }
                // Basic URL decoding for + might be needed if args are URL-encoded in POST body
                // for (char *p = balcon_args; *p; ++p) if (*p == '+') *p = ' ';
                // For full URL decoding, use mg_url_decode if available and necessary.
            } else if (hm->body.len > 0 && hm->body.len < sizeof(balcon_args) -1) {
                 // Fallback: If no "args=" and body is short, assume entire body is plain text args
                 strncpy(balcon_args, hm->body.buf, hm->body.len);
                 balcon_args[hm->body.len] = '\0';
            }
        }
      }

      if (balcon_args[0] != '\0') {
        // Construct the command: "C:\path\to\script.bat" arguments_for_balcon
        snprintf(command_to_run, sizeof(command_to_run), "cmd /C \"\"%s\" %s\"", s_balcon_script_path, balcon_args);
        MG_INFO(("Executing Balcon script with args: %s", command_to_run));

        int system_result = system(command_to_run); 

        if (system_result == 0) {
          mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "Balcon command executed successfully.\n");
        } else {
          char error_reply_buffer[128];
          snprintf(error_reply_buffer, sizeof(error_reply_buffer), "Error executing Balcon command. Script exit code: %d\n", system_result);
          mg_http_reply(c, 500, "Content-Type: text/plain\r\n", error_reply_buffer);
        }
      } else {
        mg_http_reply(c, 400, "Content-Type: text/plain\r\n", "Missing 'args' parameter in GET query or POST body (as 'args=value').\n");
      }
      return; // Processed /balcon
    } 
    // Handle /upload endpoint (if s_upload_dir is configured)
    else if (s_upload_dir != NULL && mg_match(hm->uri, mg_str("/upload"), NULL)) {
      struct mg_http_part part;
      size_t pos = 0, total_bytes = 0, num_files = 0;
      while ((pos = mg_http_next_multipart(hm->body, pos, &part)) > 0) {
        char file_path_buffer[MG_PATH_MAX]; // MG_PATH_MAX should be defined in mongoose.h
        MG_INFO(("Chunk name: [%.*s] filename: [%.*s] length: %lu bytes",
                 (int)part.name.len, part.name.buf, 
                 (int)part.filename.len, part.filename.buf, 
                 (unsigned long)part.body.len));
        
        if (part.filename.len > 0) { // Ensure filename is not empty
            mg_snprintf(file_path_buffer, sizeof(file_path_buffer), "%s/%.*s", s_upload_dir,
                        (int)part.filename.len, part.filename.buf);

            if (mg_path_is_sane(mg_str(file_path_buffer))) {
                // Mongoose v7+ mg_file_write takes fs as first arg, can be NULL for default.
                if (mg_file_write(NULL, file_path_buffer, part.body.buf, part.body.len)) { 
                    total_bytes += part.body.len;
                    num_files++;
                } else {
                    MG_ERROR(("Failed to write file: %s", file_path_buffer));
                }
            } else {
                MG_ERROR(("Rejecting dangerous path for upload: %s", file_path_buffer));
            }
        } else {
            MG_INFO(("Skipping part with no filename. Name: [%.*s]", (int)part.name.len, part.name.buf));
        }
      }
      char reply_buf[128]; // Buffer for the reply string
      mg_snprintf(reply_buf, sizeof(reply_buf), "Uploaded %lu files, %lu bytes\n", 
                   (unsigned long)num_files, (unsigned long)total_bytes);
      mg_http_reply(c, 200, "Content-Type: text/plain\r\n", reply_buf);
      return; // Processed /upload
    } 
    // Default: Serve static files from the web root directory
    else {
      struct mg_http_serve_opts opts = {0}; // C99 struct initialization
      opts.root_dir = s_root_dir;
      opts.ssi_pattern = s_ssi_pattern;
      mg_http_serve_dir(c, hm, &opts);
    }
  }
}

static void usage(const char *prog) {
  fprintf(stderr,
          "Mongoose v.%s\n"
          "Usage: %s OPTIONS\n"
          "  -H yes|no - enable traffic hexdump, default: '%s'\n"
          "  -S PAT    - SSI filename pattern, default: '%s'\n"
          "  -d DIR    - directory to serve, default: '%s'\n"
          "  -l ADDR   - listening address, default: '%s'\n"
          "  -u DIR    - file upload directory, default: unset\n"
          "  -v LEVEL  - debug level, from 0 to 4, default: %d\n",
          MG_VERSION, prog, s_enable_hexdump, s_ssi_pattern, s_root_dir,
          s_addr1, s_debug_level);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  char path[MG_PATH_MAX] = "."; // MG_PATH_MAX should be defined in mongoose.h
  struct mg_mgr mgr;
  // struct mg_connection *c; // No longer used in main when TLS is disabled
  int i;

  // Parse command-line flags
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-d") == 0) {
      s_root_dir = argv[++i];
    } else if (strcmp(argv[i], "-H") == 0) {
      s_enable_hexdump = argv[++i];
    } else if (strcmp(argv[i], "-S") == 0) {
      s_ssi_pattern = argv[++i];
    } else if (strcmp(argv[i], "-l") == 0) {
      s_addr1 = argv[++i];
#ifndef MG_TLS_DISABLED
    } else if (strcmp(argv[i], "-l2") == 0) { // Only relevant if TLS is enabled
      s_addr2 = argv[++i];
#endif
    } else if (strcmp(argv[i], "-u") == 0) {
      s_upload_dir = argv[++i];
    } else if (strcmp(argv[i], "-v") == 0) {
      s_debug_level = atoi(argv[++i]);
    } else {
      usage(argv[0]);
    }
  }

  // Root directory must not contain double dots. Make it absolute
  if (strchr(s_root_dir, ',') == NULL) { // Do not run realpath if multiple dirs are specified
    realpath(s_root_dir, path);
    s_root_dir = path;
  }

  // Initialise stuff
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  mg_log_set(s_debug_level);
  mg_mgr_init(&mgr);

  // Setup HTTP listener
  if (mg_http_listen(&mgr, s_addr1, cb, NULL) == NULL) { // Pass NULL for user_data
    MG_ERROR(("Cannot listen on %s. Use http://ADDR:PORT or :PORT", s_addr1));
    exit(EXIT_FAILURE);
  }
  
#ifndef MG_TLS_DISABLED
  // Only attempt to set up HTTPS listener if TLS is not disabled
  if (mg_http_listen(&mgr, s_addr2, cb, NULL) == NULL) { 
    MG_ERROR(("Cannot listen on %s. Use https://ADDR:PORT", s_addr2));
    // Consider if this should be a fatal error or if HTTPS is optional
    // exit(EXIT_FAILURE); 
  }
#endif

  // Start infinite event loop
  MG_INFO(("Mongoose version : v%s", MG_VERSION));
  MG_INFO(("HTTP listener    : %s", s_addr1));
#ifndef MG_TLS_DISABLED
  MG_INFO(("HTTPS listener   : %s", s_addr2)); 
#endif
  MG_INFO(("Web root         : [%s]", s_root_dir));
  MG_INFO(("Upload dir       : [%s]", s_upload_dir ? s_upload_dir : "unset"));
  MG_INFO(("Balcon script    : [%s]", s_balcon_script_path)); 
  while (s_signo == 0) mg_mgr_poll(&mgr, 1000); // Event loop
  mg_mgr_free(&mgr); // Cleanup
  MG_INFO(("Exiting on signal %d", s_signo));
  return 0;
}