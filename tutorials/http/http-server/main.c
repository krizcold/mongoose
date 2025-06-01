// Copyright (c) 2020 Cesanta Software Limited
// All rights reserved

#include <winsock2.h> 
#include <windows.h>  
#include <signal.h>
#include <stddef.h> 
#include <string.h> 
#include <stdio.h>  
#include <stdlib.h> 
#include <errno.h>   
#include <time.h>    
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
static const char *s_balcon_wav_output_dir = "C:\\balcon\\wav_output\\"; 


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

static void delete_file(const char *filepath) {
    if (remove(filepath) == 0) {
        MG_INFO(("Successfully deleted file: %s", filepath));
    } else {
        MG_ERROR(("Error deleting file: %s (errno: %d)", filepath, errno));
    }
}

static void cleanup_wav_files_at_startup(const char *directory, int max_age_seconds) {
    WIN32_FIND_DATAA findFileData; 
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char searchPath[MG_PATH_MAX];
    char fullFilePath[MG_PATH_MAX];
    time_t now = time(NULL); 

    MG_INFO(("Performing cleanup of .wav files older than %d seconds in: %s", max_age_seconds, directory));

    char dir_with_slash[MG_PATH_MAX];
    strncpy(dir_with_slash, directory, sizeof(dir_with_slash) -1);
    dir_with_slash[sizeof(dir_with_slash)-1] = '\0';
    size_t len = strlen(dir_with_slash);
    if (len > 0 && dir_with_slash[len-1] != '\\' && dir_with_slash[len-1] != '/') {
        if (len < sizeof(dir_with_slash) - 1) {
            strncat(dir_with_slash, "\\", sizeof(dir_with_slash) - len -1);
        } else {
             MG_ERROR(("Directory path too long to append slash for cleanup: %s", directory));
             return;
        }
    }

    if (strlen(dir_with_slash) + strlen("*.wav") + 1 >= MG_PATH_MAX) {
        MG_ERROR(("Directory path too long for search pattern: %s", dir_with_slash));
        return;
    }
    snprintf(searchPath, sizeof(searchPath), "%s*.wav", dir_with_slash);
    MG_INFO(("Cleanup search path: %s", searchPath));

    hFind = FindFirstFileA(searchPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) { 
            MG_ERROR(("FindFirstFile failed for cleanup in %s. Error code: %lu", dir_with_slash, GetLastError()));
        } else {
            MG_INFO(("No .wav files found for cleanup in %s.", dir_with_slash));
        }
        return;
    }

    do {
        if (strlen(dir_with_slash) + strlen(findFileData.cFileName) + 1 >= MG_PATH_MAX) {
            MG_ERROR(("File path too long for cleanup: %s%s", dir_with_slash, findFileData.cFileName));
            continue; 
        }
        snprintf(fullFilePath, sizeof(fullFilePath), "%s%s", dir_with_slash, findFileData.cFileName);
        
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            WIN32_FILE_ATTRIBUTE_DATA fileAttrData;
            if (GetFileAttributesExA(fullFilePath, GetFileExInfoStandard, &fileAttrData)) {
                ULARGE_INTEGER ull;
                ull.LowPart = fileAttrData.ftLastWriteTime.dwLowDateTime;
                ull.HighPart = fileAttrData.ftLastWriteTime.dwHighDateTime;
                time_t file_mod_time = (time_t)(ull.QuadPart / 10000000ULL - 11644473600ULL);
                double age_seconds = difftime(now, file_mod_time);

                MG_INFO(("File: %s, ModTime_RawLow: %lu, ModTime_RawHigh: %lu, ModTime_Epoch: %lld, Now_Epoch: %lld, Age_Calculated: %.0f sec, MaxAge: %d", 
                        fullFilePath, 
                        fileAttrData.ftLastWriteTime.dwLowDateTime, 
                        fileAttrData.ftLastWriteTime.dwHighDateTime,
                        (long long)file_mod_time, 
                        (long long)now, 
                        age_seconds,
                        max_age_seconds));

                if (age_seconds > max_age_seconds) {
                    MG_INFO(("Action: DELETING old file: %s", fullFilePath));
                    delete_file(fullFilePath);
                } else {
                    MG_INFO(("Action: KEEPING recent file: %s", fullFilePath));
                }
            } else {
                 MG_ERROR(("Could not get file attributes for: %s. Error: %lu", fullFilePath, GetLastError()));
            }
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);

    FindClose(hFind);
    DWORD dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES) { 
        MG_ERROR(("Error during FindNextFileA for cleanup. Error code: %lu", dwError));
    }
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
    struct mg_tls_opts tls_opts_conn;
    memset(&tls_opts_conn, 0, sizeof(tls_opts_conn));
#ifdef TLS_TWOWAY 
    tls_opts_conn.ca = mg_str(s_tls_ca); 
#endif
    tls_opts_conn.cert = mg_str(s_tls_cert);
    tls_opts_conn.key = mg_str(s_tls_key);
    mg_tls_init(c, &tls_opts_conn); 
  } else 
#endif
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    MG_INFO(("%.*s %.*s", (int) hm->method.len, hm->method.buf, (int) hm->uri.len, hm->uri.buf));

    if (mg_match(hm->uri, mg_str("/balcon"), NULL)) {
      char balcon_args_original_unescaped[4096] = ""; 
      char balcon_args_modified_for_system[4096] = "";
      char command_to_run[4200];    
      char requested_wav_basename[256] = ""; 
      char full_wav_path_for_serving_and_delete[MG_PATH_MAX]; 

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
                  temp_args_buffer[post_body_len] = '\0'; 
              }
              temp_args_buffer[sizeof(temp_args_buffer)-1] = '\0'; 
          }
      }
      temp_args_buffer[sizeof(temp_args_buffer)-1] = '\0';

      strncpy(balcon_args_original_unescaped, temp_args_buffer, sizeof(balcon_args_original_unescaped) - 1);
      balcon_args_original_unescaped[sizeof(balcon_args_original_unescaped) - 1] = '\0';
      mg_url_decode(balcon_args_original_unescaped, strlen(balcon_args_original_unescaped), balcon_args_original_unescaped, sizeof(balcon_args_original_unescaped), 0);

      if (balcon_args_original_unescaped[0] != '\0') {
        const char *extracted_basename = extract_wav_filename(balcon_args_original_unescaped);
        if (extracted_basename && strlen(extracted_basename) > 0) {
            strncpy(requested_wav_basename, extracted_basename, sizeof(requested_wav_basename) - 1);
            requested_wav_basename[sizeof(requested_wav_basename) - 1] = '\0';
            MG_INFO(("Original balcon args: [%s]", balcon_args_original_unescaped));
            MG_INFO(("Requested output WAV basename: %s", requested_wav_basename));

            char wav_output_path_for_w_arg[MG_PATH_MAX];
            char dir_with_slash_wav_out_local[MG_PATH_MAX]; 
            strncpy(dir_with_slash_wav_out_local, s_balcon_wav_output_dir, sizeof(dir_with_slash_wav_out_local) -1);
            dir_with_slash_wav_out_local[sizeof(dir_with_slash_wav_out_local)-1] = '\0';
            size_t len_wav_out_local = strlen(dir_with_slash_wav_out_local);
            if (len_wav_out_local > 0 && dir_with_slash_wav_out_local[len_wav_out_local-1] != '\\' && dir_with_slash_wav_out_local[len_wav_out_local-1] != '/') {
                if (len_wav_out_local < sizeof(dir_with_slash_wav_out_local) - 1) strncat(dir_with_slash_wav_out_local, "\\", sizeof(dir_with_slash_wav_out_local) - len_wav_out_local - 1);
            }
            snprintf(wav_output_path_for_w_arg, sizeof(wav_output_path_for_w_arg), 
                     "%s%s", dir_with_slash_wav_out_local, requested_wav_basename);

            const char *w_option_ptr = strstr(balcon_args_original_unescaped, "-w");
            if (w_option_ptr) { 
                size_t prefix_len = w_option_ptr - balcon_args_original_unescaped;
                strncpy(balcon_args_modified_for_system, balcon_args_original_unescaped, prefix_len);
                balcon_args_modified_for_system[prefix_len] = '\0';
                
                size_t current_len_modified_args = prefix_len;
                current_len_modified_args += snprintf(balcon_args_modified_for_system + prefix_len, 
                                                     sizeof(balcon_args_modified_for_system) - prefix_len,
                                                     "-w \"%s\"", wav_output_path_for_w_arg);

                const char *ptr_after_w_keyword = w_option_ptr + 2; 
                while (*ptr_after_w_keyword == ' ' || *ptr_after_w_keyword == '\t') ptr_after_w_keyword++; 

                const char *start_of_original_filename_in_args = ptr_after_w_keyword;
                const char *end_of_original_filename_in_args;

                if (*start_of_original_filename_in_args == '"') { 
                    end_of_original_filename_in_args = strchr(start_of_original_filename_in_args + 1, '"');
                    if (end_of_original_filename_in_args) {
                        end_of_original_filename_in_args++; 
                    } else { 
                        end_of_original_filename_in_args = start_of_original_filename_in_args + strlen(start_of_original_filename_in_args);
                    }
                } else { 
                    end_of_original_filename_in_args = start_of_original_filename_in_args;
                    while (*end_of_original_filename_in_args != '\0' && *end_of_original_filename_in_args != ' ' && *end_of_original_filename_in_args != '\t') {
                        end_of_original_filename_in_args++;
                    }
                }
                
                if (*end_of_original_filename_in_args != '\0' && current_len_modified_args < sizeof(balcon_args_modified_for_system) - 1) {
                     balcon_args_modified_for_system[current_len_modified_args++] = ' ';
                     balcon_args_modified_for_system[current_len_modified_args] = '\0'; 
                }

                if (*end_of_original_filename_in_args != '\0' && current_len_modified_args < sizeof(balcon_args_modified_for_system) - 1) {
                    strncat(balcon_args_modified_for_system, end_of_original_filename_in_args, 
                            sizeof(balcon_args_modified_for_system) - current_len_modified_args - 1);
                }
                balcon_args_modified_for_system[sizeof(balcon_args_modified_for_system)-1] = '\0';
            } else { 
                strncpy(balcon_args_modified_for_system, balcon_args_original_unescaped, sizeof(balcon_args_modified_for_system) -1);
                balcon_args_modified_for_system[sizeof(balcon_args_modified_for_system)-1] = '\0';
            }
        } else { 
            MG_INFO(("No -w option found in balcon args. Balcon will not save a file. Passing original args."));
            strncpy(balcon_args_modified_for_system, balcon_args_original_unescaped, sizeof(balcon_args_modified_for_system) -1);
            balcon_args_modified_for_system[sizeof(balcon_args_modified_for_system)-1] = '\0';
        }

        snprintf(command_to_run, sizeof(command_to_run), "cmd /C \"\"%s\" %s\"", s_balcon_script_path, balcon_args_modified_for_system);
        MG_INFO(("Executing Balcon script with MODIFIED args: %s", command_to_run));
        int system_result = system(command_to_run); 

        if (system_result == 0) {
          if (requested_wav_basename[0] != '\0') { 
            char dir_with_slash_wav_out_serve[MG_PATH_MAX]; 
            strncpy(dir_with_slash_wav_out_serve, s_balcon_wav_output_dir, sizeof(dir_with_slash_wav_out_serve) -1);
            dir_with_slash_wav_out_serve[sizeof(dir_with_slash_wav_out_serve)-1] = '\0';
            size_t len_wav_out_serve = strlen(dir_with_slash_wav_out_serve);
            if (len_wav_out_serve > 0 && dir_with_slash_wav_out_serve[len_wav_out_serve-1] != '\\' && dir_with_slash_wav_out_serve[len_wav_out_serve-1] != '/') {
                if (len_wav_out_serve < sizeof(dir_with_slash_wav_out_serve) - 1) strncat(dir_with_slash_wav_out_serve, "\\", sizeof(dir_with_slash_wav_out_serve) - len_wav_out_serve - 1);
            }
            snprintf(full_wav_path_for_serving_and_delete, sizeof(full_wav_path_for_serving_and_delete), 
                     "%s%s", dir_with_slash_wav_out_serve, requested_wav_basename);
            
            FILE *fp_check = fopen(full_wav_path_for_serving_and_delete, "rb"); 
            if (fp_check) {
                fclose(fp_check); 
                MG_INFO(("Attempting to serve WAV file using ABSOLUTE path: %s", full_wav_path_for_serving_and_delete));
                
                struct mg_http_serve_opts opts = {0};
                char extra_headers[512];
                snprintf(extra_headers, sizeof(extra_headers), 
                         "Content-Type: audio/wav\r\n"
                         "Content-Disposition: attachment; filename=\"%s\"\r\n"
                         "Access-Control-Allow-Origin: *\r\n", 
                         requested_wav_basename); 
                opts.root_dir = NULL; 
                opts.extra_headers = extra_headers;
                
                mg_http_serve_file(c, hm, full_wav_path_for_serving_and_delete, &opts); 
                // File is NOT deleted here. Cleanup is by startup/periodic.
              } else {
                MG_ERROR(("Generated WAV file not found or not readable: %s", full_wav_path_for_serving_and_delete));
                mg_http_reply(c, 500, "Content-Type: text/plain\r\n", "Balcon command ran, but output WAV file not found.\n");
              }
          } else { 
            mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "Balcon command executed (no WAV output file requested).\n");
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

      while ((pos = mg_http_next_multipart(hm->body, pos, &part)) > 0) {
        MG_INFO(("Chunk name: [%.*s] filename: [%.*s] length: %lu bytes",
                 (int)part.name.len, part.name.buf, 
                 (int)part.filename.len, part.filename.buf, 
                 (unsigned long)part.body.len));
        
        if (part.filename.len > 0) { 
            if (first_part_for_file) {
                char dir_with_slash_upload[MG_PATH_MAX]; 
                strncpy(dir_with_slash_upload, s_upload_dir, sizeof(dir_with_slash_upload) -1);
                dir_with_slash_upload[sizeof(dir_with_slash_upload)-1] = '\0';
                size_t len_up = strlen(dir_with_slash_upload);
                if (len_up > 0 && dir_with_slash_upload[len_up-1] != '\\' && dir_with_slash_upload[len_up-1] != '/') {
                     if (len_up < sizeof(dir_with_slash_upload) - 1) strncat(dir_with_slash_upload, "\\", sizeof(dir_with_slash_upload) - len_up - 1);
                }

                mg_snprintf(file_path_buffer, sizeof(file_path_buffer), "%s%.*s", dir_with_slash_upload,
                            (int)part.filename.len, part.filename.buf);
                MG_INFO(("Opening file for writing: [%s]", file_path_buffer));
                
                if (!mg_path_is_sane(mg_str(file_path_buffer))) {
                    MG_ERROR(("Rejecting dangerous path for upload: %s", file_path_buffer));
                    if (fp_upload) { fclose(fp_upload); fp_upload = NULL; } 
                    break; 
                }
                fp_upload = fopen(file_path_buffer, "wb"); 
                if (fp_upload == NULL) {
                    MG_ERROR(("Manual fopen failed for %s. errno: %d", file_path_buffer, errno)); 
                    break; 
                }
                first_part_for_file = false; 
            }

            if (fp_upload) { 
                MG_INFO(("Writing %lu bytes to %s", (unsigned long)part.body.len, file_path_buffer));
                size_t bytes_written = fwrite(part.body.buf, 1, part.body.len, fp_upload);
                if (bytes_written == part.body.len) {
                    MG_INFO(("Successfully wrote %lu bytes manually to %s", (unsigned long)bytes_written, file_path_buffer));
                    total_bytes += bytes_written;
                } else {
                    MG_ERROR(("Manual fwrite error: wrote %lu of %lu bytes to %s. Error flag: %d, errno: %d", 
                              (unsigned long)bytes_written, (unsigned long)part.body.len, file_path_buffer, ferror(fp_upload), errno));
                    fclose(fp_upload); 
                    fp_upload = NULL;
                    break; 
                }
            }
        } else {
            MG_INFO(("Skipping part with no filename. Name: [%.*s]", (int)part.name.len, part.name.buf));
        }
      } 

      if (fp_upload != NULL) {
          fclose(fp_upload);
          fp_upload = NULL;
          if (total_bytes > 0) num_files = 1; 
          MG_INFO(("Finished writing and closed file: %s (Total bytes: %lu)", file_path_buffer, (unsigned long)total_bytes));
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
  #define WAV_FILE_MAX_AGE_SECONDS (5 * 60) 
  #define CLEANUP_INTERVAL_SECONDS (5 * 60)     // Check every 5 minutes

  time_t last_cleanup_time = time(NULL); 

  cleanup_wav_files_at_startup(s_balcon_wav_output_dir, WAV_FILE_MAX_AGE_SECONDS); 

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

  if (strchr(s_root_dir, ',') == NULL) { 
    if(realpath(s_root_dir, path) != NULL) s_root_dir = path; 
  }
  
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
  MG_INFO(("Balcon WAV output dir: [%s]", s_balcon_wav_output_dir)); 
  
  while (s_signo == 0) {
    mg_mgr_poll(&mgr, 1000); 

    time_t current_time = time(NULL);
    if (difftime(current_time, last_cleanup_time) >= CLEANUP_INTERVAL_SECONDS) {
      MG_INFO(("-- Periodic WAV file cleanup triggered --"));
      cleanup_wav_files_at_startup(s_balcon_wav_output_dir, WAV_FILE_MAX_AGE_SECONDS);
      last_cleanup_time = current_time;
    }
  } 
  
  mg_mgr_free(&mgr); 
  MG_INFO(("Exiting on signal %d", s_signo));
  return 0;
}
