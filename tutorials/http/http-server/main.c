// Copyright (c) 2020 Cesanta Software Limited
// All rights reserved

#include <signal.h>
#include <stddef.h> 
#include <string.h> 
#include <stdio.h>  
#include <stdlib.h> 
#include <errno.h>
#include "mongoose.h"

static int s_debug_level = MG_LL_INFO;
static const char *s_root_dir = "C:\\balcon\\"; 
static const char *s_addr1 = "http://0.0.0.0:8000";
#ifndef MG_TLS_DISABLED
static const char *s_addr2 = "https://0.0.0.0:8443"; 
#endif
static const char *s_enable_hexdump = "no";
static const char *s_ssi_pattern = "#.html";
static const char *s_upload_dir = "C:\\balcon\\uploads\\"; 

static const char *s_balcon_script_path = "C:\\balcon\\run_balcon.bat";
static const char *s_balcon_output_dir = "C:\\balcon\\"; 


#ifndef MG_TLS_DISABLED
#ifdef TLS_TWOWAY 
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
#endif 

static int s_signo;
static void signal_handler(int signo) {
  s_signo = signo;
}

const char *extract_wav_filename(const char *balcon_args_input) {
    const char *w_option = strstr(balcon_args_input, "-w");
    if (w_option) {
        const char *filename_start = w_option + 2; 
        while (*filename_start == ' ' || *filename_start == '\t') { 
            filename_start++;
        }
        if (*filename_start == '\0') return NULL; 

        if (*filename_start == '"') {
            filename_start++; 
            const char *filename_end = strchr(filename_start, '"');
            if (filename_end) {
                static char temp_filename[256]; 
                size_t len = filename_end - filename_start;
                if (len < sizeof(temp_filename)) {
                    strncpy(temp_filename, filename_start, len);
                    temp_filename[len] = '\0';
                    return temp_filename;
                }
                return NULL; 
            } else {
                return NULL; 
            }
        } else {
            const char *filename_end = filename_start;
            while (*filename_end != '\0' && *filename_end != ' ' && *filename_end != '\t') {
                filename_end++;
            }
            static char temp_filename[256];
            size_t len = filename_end - filename_start;
             if (len < sizeof(temp_filename)) {
                strncpy(temp_filename, filename_start, len);
                temp_filename[len] = '\0';
                return temp_filename;
            }
            return NULL; 
        }
    }
    return NULL;
}


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
    mg_tls_init(c, &opts); 
  } else 
#endif
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    MG_INFO(("%.*s %.*s", (int) hm->method.len, hm->method.buf, (int) hm->uri.len, hm->uri.buf));

    if (mg_match(hm->uri, mg_str("/balcon"), NULL)) {
      char balcon_args_unescaped[4096] = ""; 
      char command_to_run[4200];    
      char requested_wav_filename[256] = ""; 
      char full_wav_path[MG_PATH_MAX];       

      char temp_args_buffer[4096] = "";
      mg_http_get_var(&hm->query, "args", temp_args_buffer, sizeof(temp_args_buffer) -1);
      if (temp_args_buffer[0] == '\0' && mg_match(hm->method, mg_str("POST"), NULL)) {
          if (hm->body.len > 0 && hm->body.len < sizeof(temp_args_buffer) -1 ) {
              const char* post_body_str = hm->body.buf;
              size_t post_body_len = hm->body.len;
              if (strncmp(post_body_str, "args=", 5) == 0) {
                  strncpy(temp_args_buffer, post_body_str + 5, sizeof(temp_args_buffer) -1 );
              } else {
                  strncpy(temp_args_buffer, post_body_str, post_body_len);
                  temp_args_buffer[post_body_len] = '\0'; // Ensure null termination if strncpy doesn't fill
              }
              temp_args_buffer[sizeof(temp_args_buffer)-1] = '\0'; // Ensure null termination
          }
      }
      temp_args_buffer[sizeof(temp_args_buffer)-1] = '\0';

      strncpy(balcon_args_unescaped, temp_args_buffer, sizeof(balcon_args_unescaped) - 1);
      balcon_args_unescaped[sizeof(balcon_args_unescaped) - 1] = '\0';
      mg_url_decode(balcon_args_unescaped, strlen(balcon_args_unescaped), balcon_args_unescaped, sizeof(balcon_args_unescaped), 0);

      if (balcon_args_unescaped[0] != '\0') {
        const char *extracted_filename = extract_wav_filename(balcon_args_unescaped);
        if (extracted_filename && strlen(extracted_filename) > 0) {
            strncpy(requested_wav_filename, extracted_filename, sizeof(requested_wav_filename) - 1);
            requested_wav_filename[sizeof(requested_wav_filename) - 1] = '\0';
            MG_INFO(("Requested output WAV filename: %s", requested_wav_filename));
        } else {
            MG_INFO(("No -w option found or filename is empty in balcon args. Cannot serve file back."));
        }

        snprintf(command_to_run, sizeof(command_to_run), "cmd /C \"\"%s\" %s\"", s_balcon_script_path, balcon_args_unescaped);
        MG_INFO(("Executing Balcon script: %s", command_to_run));
        int system_result = system(command_to_run); 

        if (system_result == 0) {
          if (requested_wav_filename[0] != '\0') {
            snprintf(full_wav_path, sizeof(full_wav_path), "%s%s", s_balcon_output_dir, requested_wav_filename);
            FILE *fp_wav = fopen(full_wav_path, "rb");
            if (fp_wav) {
                fclose(fp_wav);
                MG_INFO(("Attempting to serve WAV file: %s", full_wav_path));
                char extra_headers[512];
                snprintf(extra_headers, sizeof(extra_headers), 
                         "Content-Disposition: attachment; filename=\"%s\"\r\n"
                         "Access-Control-Allow-Origin: *\r\n", 
                         requested_wav_filename);
                struct mg_http_serve_opts opts = {0};
                opts.root_dir = s_balcon_output_dir; 
                opts.extra_headers = extra_headers;
                mg_http_serve_file(c, hm, requested_wav_filename, &opts);
              } else {
                MG_ERROR(("Generated WAV file not found or not readable: %s", full_wav_path));
                mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "Balcon command ran, but output WAV file not found.\n");
              }
          } else {
            mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "Balcon command executed (no WAV filename specified for serving).\n");
          }
        } else {
          char error_reply_buffer[128];
          snprintf(error_reply_buffer, sizeof(error_reply_buffer), "Error executing Balcon command. Script exit code: %d\n", system_result);
          mg_http_reply(c, 500, "Content-Type: text/plain\r\n", error_reply_buffer);
        }
      } else {
        mg_http_reply(c, 400, "Content-Type: text/plain\r\n", "Missing 'args' parameter.\n");
      }
      return; 
    } 
    else if (s_upload_dir != NULL && mg_match(hm->uri, mg_str("/upload"), NULL)) {
      struct mg_http_part part;
      size_t pos = 0, total_bytes = 0, num_files = 0;
      char file_path_buffer[MG_PATH_MAX]; 
      FILE *fp_upload = NULL;
      bool first_part_for_file = true;

      // Loop through multipart parts
      while ((pos = mg_http_next_multipart(hm->body, pos, &part)) > 0) {
        MG_INFO(("Chunk name: [%.*s] filename: [%.*s] length: %lu bytes",
                 (int)part.name.len, part.name.buf, 
                 (int)part.filename.len, part.filename.buf, 
                 (unsigned long)part.body.len));
        
        if (part.filename.len > 0) { // This part is a file
            if (first_part_for_file) {
                // Construct path and open file only for the first part with this filename
                mg_snprintf(file_path_buffer, sizeof(file_path_buffer), "%s\\%.*s", s_upload_dir,
                            (int)part.filename.len, part.filename.buf);
                MG_INFO(("Opening file for writing: [%s]", file_path_buffer));
                
                if (!mg_path_is_sane(mg_str(file_path_buffer))) {
                    MG_ERROR(("Rejecting dangerous path for upload: %s", file_path_buffer));
                    if (fp_upload) { fclose(fp_upload); fp_upload = NULL; } // Close if opened by a previous bad part
                    break; // Stop processing this upload
                }
                fp_upload = fopen(file_path_buffer, "wb"); // Open in write binary mode
                if (fp_upload == NULL) {
                    MG_ERROR(("Manual fopen failed for %s. errno: %d", file_path_buffer, errno)); 
                    break; // Stop processing this upload
                }
                first_part_for_file = false; // Subsequent parts append to this opened file
            }

            if (fp_upload) { // If file is successfully opened
                MG_INFO(("Writing %lu bytes to %s", (unsigned long)part.body.len, file_path_buffer));
                size_t bytes_written = fwrite(part.body.buf, 1, part.body.len, fp_upload);
                if (bytes_written == part.body.len) {
                    fflush(fp_upload); // Flush after each successful chunk write
                    MG_INFO(("Successfully wrote %lu bytes manually to %s", (unsigned long)bytes_written, file_path_buffer));
                    total_bytes += bytes_written;
                    // num_files is tricky here, it's one file but multiple parts. 
                    // Let's increment only if it's the first part that successfully opens/writes.
                    if (total_bytes == bytes_written) num_files++; // Count as one file if first write
                } else {
                    MG_ERROR(("Manual fwrite error: wrote %lu of %lu bytes to %s. Error flag: %d, errno: %d", 
                              (unsigned long)bytes_written, (unsigned long)part.body.len, file_path_buffer, ferror(fp_upload), errno));
                    fclose(fp_upload); // Close on error
                    fp_upload = NULL;
                    break; // Stop processing this upload
                }
            }
        } else {
            MG_INFO(("Skipping part with no filename. Name: [%.*s]", (int)part.name.len, part.name.buf));
        }
      } // End of while loop for multipart parts

      // Close the file if it was opened
      if (fp_upload != NULL) {
          fclose(fp_upload);
          fp_upload = NULL;
          MG_INFO(("Finished writing and closed file: %s", file_path_buffer));
      }

      char reply_buf[128]; 
      mg_snprintf(reply_buf, sizeof(reply_buf), "Uploaded %lu file(s), %lu bytes total\n", 
                   (unsigned long)num_files, (unsigned long)total_bytes);
      mg_http_reply(c, 200, "Content-Type: text/plain\r\n", reply_buf);
      return; 
    } 
    else { 
      struct mg_http_serve_opts opts = {0}; 
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
          "  -u DIR    - file upload directory, default: '%s'\n"
          "  -v LEVEL  - debug level, from 0 to 4, default: %d\n",
          MG_VERSION, prog, s_enable_hexdump, s_ssi_pattern, s_root_dir,
          s_addr1, s_upload_dir ? s_upload_dir : "unset" , s_debug_level);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  char path[MG_PATH_MAX] = "."; 
  struct mg_mgr mgr;
  int i;
  char *upload_dir_dynamic = NULL; // For strdup if s_upload_dir comes from argv

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
    } else if (strcmp(argv[i], "-l2") == 0) { 
      s_addr2 = argv[++i];
#endif
    } else if (strcmp(argv[i], "-u") == 0) {
      s_upload_dir = argv[++i]; // If -u is used, s_upload_dir points to argv string
    } else if (strcmp(argv[i], "-v") == 0) {
      s_debug_level = atoi(argv[++i]);
    } else {
      usage(argv[0]);
    }
  }

  if (strchr(s_root_dir, ',') == NULL) { 
    if(realpath(s_root_dir, path) != NULL) s_root_dir = path; 
  }

  // Resolve s_upload_dir if it's set and not a comma-separated list (for logging/validation)
  // s_upload_dir itself remains the const char * set by default or argv.
  if (s_upload_dir && strchr(s_upload_dir, ',') == NULL) {
    char upload_path_resolved_buf[MG_PATH_MAX];
    if(realpath(s_upload_dir, upload_path_resolved_buf) != NULL) {
      if (strcmp(s_upload_dir, upload_path_resolved_buf) != 0) {
        MG_INFO(("Upload directory configured as [%s], resolves to [%s]", s_upload_dir, upload_path_resolved_buf));
      }
    } else {
      MG_INFO(("Could not resolve upload directory path: [%s]", s_upload_dir));
    }
  }

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  mg_log_set(s_debug_level);
  mg_mgr_init(&mgr);

  if (mg_http_listen(&mgr, s_addr1, cb, NULL) == NULL) { 
    MG_ERROR(("Cannot listen on %s. Use http://ADDR:PORT or :PORT", s_addr1));
    exit(EXIT_FAILURE);
  }
  
#ifndef MG_TLS_DISABLED
  if (mg_http_listen(&mgr, s_addr2, cb, NULL) == NULL) { 
    MG_ERROR(("Cannot listen on %s. Use https://ADDR:PORT", s_addr2));
  }
#endif

  MG_INFO(("Mongoose version : v%s", MG_VERSION));
  MG_INFO(("HTTP listener    : %s", s_addr1));
#ifndef MG_TLS_DISABLED
  MG_INFO(("HTTPS listener   : %s", s_addr2)); 
#endif
  MG_INFO(("Web root         : [%s]", s_root_dir));
  MG_INFO(("Upload dir       : [%s]", s_upload_dir ? s_upload_dir : "unset"));
  MG_INFO(("Balcon script    : [%s]", s_balcon_script_path)); 
  MG_INFO(("Balcon output dir: [%s]", s_balcon_output_dir));
  while (s_signo == 0) mg_mgr_poll(&mgr, 1000); 
  mg_mgr_free(&mgr); 
  MG_INFO(("Exiting on signal %d", s_signo));
  if (upload_dir_dynamic) free(upload_dir_dynamic); 
  return 0;
}
