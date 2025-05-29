// Copyright (c) 2020 Cesanta Software Limited
// All rights reserved

#include <signal.h>
#include <stddef.h> 
#include <string.h> 
#include <stdio.h>  
#include <stdlib.h> 
#include "mongoose.h"

static int s_debug_level = MG_LL_INFO;
static const char *s_root_dir = "C:\\balcon\\"; // Let's make webroot C:\balcon for serving files
static const char *s_addr1 = "http://0.0.0.0:8000";
#ifndef MG_TLS_DISABLED
static const char *s_addr2 = "https://0.0.0.0:8443"; 
#endif
static const char *s_enable_hexdump = "no";
static const char *s_ssi_pattern = "#.html";
static const char *s_upload_dir = "C:\\balcon\\uploads"; // Upload dir

static const char *s_balcon_script_path = "C:\\balcon\\run_balcon.bat";
static const char *s_balcon_output_dir = "C:\\balcon\\"; // Directory where balcon.exe saves WAV files


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

// Helper function to extract filename from balcon's -w argument
// Very basic parser: looks for "-w" then the next token.
// Returns a pointer within balcon_args_input, or NULL.
// The caller should copy the result if it needs to persist beyond balcon_args_input's lifetime or modification.
const char *extract_wav_filename(const char *balcon_args_input) {
    const char *w_option = strstr(balcon_args_input, "-w");
    if (w_option) {
        const char *filename_start = w_option + 2; // Skip "-w"
        while (*filename_start == ' ' || *filename_start == '\t') { // Skip whitespace
            filename_start++;
        }
        if (*filename_start == '\0') return NULL; // No filename after -w

        // Check if filename is quoted
        if (*filename_start == '"') {
            filename_start++; // Skip opening quote
            const char *filename_end = strchr(filename_start, '"');
            if (filename_end) {
                // For simplicity, we're assuming the filename itself doesn't contain quotes.
                // This simple parser doesn't handle escaped quotes within a quoted filename.
                // We'll just return the start. The actual filename length would be filename_end - filename_start.
                // For serving, we'll reconstruct the full path and let mg_http_serve_file handle it.
                // What we mostly need is the base name.
                static char temp_filename[256]; // Static buffer for the extracted name
                size_t len = filename_end - filename_start;
                if (len < sizeof(temp_filename)) {
                    strncpy(temp_filename, filename_start, len);
                    temp_filename[len] = '\0';
                    return temp_filename;
                }
                return NULL; // Filename too long for buffer
            } else {
                return NULL; // Unmatched quote
            }
        } else {
            // Not quoted, find end by space or end of string
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
            return NULL; // Filename too long
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
      char balcon_args_unescaped[4096] = ""; // For unescaped args from query/POST
      char command_to_run[4200];    
      char requested_wav_filename[256] = ""; // To store the -w filename
      char full_wav_path[MG_PATH_MAX];       // Full path to the generated WAV

      // Get 'args' from query string (for GET) or POST body
      char temp_args_buffer[4096] = "";
      mg_http_get_var(&hm->query, "args", temp_args_buffer, sizeof(temp_args_buffer) -1);
      if (temp_args_buffer[0] == '\0' && mg_match(hm->method, mg_str("POST"), NULL)) {
          // Simplified POST 'args' extraction (assumes 'args=value' or plain text body if short)
          if (hm->body.len > 0 && hm->body.len < sizeof(temp_args_buffer) -1 ) {
              const char* post_body_str = hm->body.buf;
              size_t post_body_len = hm->body.len;
              if (strncmp(post_body_str, "args=", 5) == 0) {
                  strncpy(temp_args_buffer, post_body_str + 5, sizeof(temp_args_buffer) -1 );
                  temp_args_buffer[sizeof(temp_args_buffer)-1] = '\0';
              } else {
                  strncpy(temp_args_buffer, post_body_str, post_body_len);
                  temp_args_buffer[post_body_len] = '\0';
              }
          }
      }
      temp_args_buffer[sizeof(temp_args_buffer)-1] = '\0';


      // URL decode the arguments from temp_args_buffer into balcon_args_unescaped
      // Mongoose's mg_url_decode is good for this. It decodes in-place.
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
            // No specific filename means we can't easily serve it back with this logic.
            // You could default to a name, or just execute without serving.
        }

        // IMPORTANT: For system() and cmd /C, arguments with spaces or special characters
        // often need to be quoted again, even if they were URL decoded.
        // The balcon_args_unescaped should be fine for run_balcon.bat as it passes %*
        snprintf(command_to_run, sizeof(command_to_run), "cmd /C \"\"%s\" %s\"", s_balcon_script_path, balcon_args_unescaped);
        MG_INFO(("Executing Balcon script: %s", command_to_run));

        int system_result = system(command_to_run); 

        if (system_result == 0) {
          if (requested_wav_filename[0] != '\0') {
            snprintf(full_wav_path, sizeof(full_wav_path), "%s%s", s_balcon_output_dir, requested_wav_filename);
            
            // Check if file exists before trying to serve
            FILE *fp = fopen(full_wav_path, "rb");
            if (fp) {
                fclose(fp);
                MG_INFO(("Attempting to serve WAV file: %s", full_wav_path));
                // Set headers for file download
                // mg_http_serve_file will set Content-Type based on extension if possible.
                // We can add Content-Disposition to suggest a filename to the browser.
                char extra_headers[512];
                snprintf(extra_headers, sizeof(extra_headers), 
                         "Content-Disposition: attachment; filename=\"%s\"\r\n"
                         "Access-Control-Allow-Origin: *\r\n", // CORS header for broader client access
                         requested_wav_filename);

                struct mg_http_serve_opts opts = {0};
                opts.root_dir = s_balcon_output_dir; // Serve from the output directory
                opts.extra_headers = extra_headers;
                
                // Mongoose needs filename relative to root_dir for mg_http_serve_file
                mg_http_serve_file(c, hm, requested_wav_filename, &opts);
                
                // Delete the file after serving

                // !!!!!!!!!!!!!!!!!!!!!!

                // REMINDER TO UNCOMMENT THE FILE DELETION CODE BELOW

                // !!!!!!!!!!!!!!!!!!!!!!!!!!

                // if (remove(full_wav_path) == 0) {
                //   MG_INFO(("Successfully deleted served WAV file: %s", full_wav_path));
                // } else {
                //   MG_ERROR(("Error deleting served WAV file: %s", full_wav_path));
                // }
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
    // ... (rest of /upload and static file serving logic from previous version) ...
    else if (s_upload_dir != NULL && mg_match(hm->uri, mg_str("/upload"), NULL)) {
      struct mg_http_part part;
      size_t pos = 0, total_bytes = 0, num_files = 0;
      while ((pos = mg_http_next_multipart(hm->body, pos, &part)) > 0) {
        char file_path_buffer[MG_PATH_MAX]; 
        MG_INFO(("Chunk name: [%.*s] filename: [%.*s] length: %lu bytes",
                 (int)part.name.len, part.name.buf, 
                 (int)part.filename.len, part.filename.buf, 
                 (unsigned long)part.body.len));
        
        if (part.filename.len > 0) { 
            mg_snprintf(file_path_buffer, sizeof(file_path_buffer), "%s\\%.*s", s_upload_dir, // Use backslash for Windows paths
                        (int)part.filename.len, part.filename.buf);

            if (mg_path_is_sane(mg_str(file_path_buffer))) {
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
      char reply_buf[128]; 
      mg_snprintf(reply_buf, sizeof(reply_buf), "Uploaded %lu files, %lu bytes\n", 
                   (unsigned long)num_files, (unsigned long)total_bytes);
      mg_http_reply(c, 200, "Content-Type: text/plain\r\n", reply_buf);
      return; 
    } 
    else { // Serve static files from s_root_dir
      struct mg_http_serve_opts opts = {0}; 
      opts.root_dir = s_root_dir;
      opts.ssi_pattern = s_ssi_pattern; 
      // Example: Serve index.html if URI is "/"
      // if (mg_match(hm->uri, mg_str("/"), NULL) || mg_match(hm->uri, mg_str("/index.html"), NULL)) {
      //    mg_http_serve_file(c, hm, "index.html", &opts);
      //} else {
          mg_http_serve_dir(c, hm, &opts);
      //}
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

  // Default s_root_dir (can be overridden by -d)
  // If s_upload_dir is not set by command line, you could default it here if desired.
  // e.g., if (s_upload_dir == NULL) s_upload_dir = "C:\\balcon\\uploads";


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
      s_upload_dir = argv[++i];
    } else if (strcmp(argv[i], "-v") == 0) {
      s_debug_level = atoi(argv[++i]);
    } else {
      usage(argv[0]);
    }
  }

  // Ensure s_balcon_output_dir ends with a path separator if it's used for concatenation
  // (It's already defined with one, so this is just a safety check concept)
  // size_t len_out_dir = strlen(s_balcon_output_dir);
  // if (len_out_dir > 0 && s_balcon_output_dir[len_out_dir - 1] != '\\' && s_balcon_output_dir[len_out_dir - 1] != '/') {
  //    // This would require s_balcon_output_dir to be non-const or use a temp buffer
  // }


  if (strchr(s_root_dir, ',') == NULL) { 
    if(realpath(s_root_dir, path) != NULL) s_root_dir = path; // Use resolved path if successful
  }
  if (s_upload_dir && strchr(s_upload_dir, ',') == NULL) {
      char upload_path_resolved[MG_PATH_MAX];
      if(realpath(s_upload_dir, upload_path_resolved) != NULL) s_upload_dir = strdup(upload_path_resolved); // strdup to make it modifiable if needed
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

  // Start infinite event loop
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
  if (s_upload_dir && strchr(s_upload_dir, ',') == NULL) free((void *)s_upload_dir); // Free duplicated string
  return 0;
}