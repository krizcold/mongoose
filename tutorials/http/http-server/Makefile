PROG ?= http_server             # Program we are building
DELETE = rm -rf                   # Command to remove files
OUT ?= -o $(PROG)                 # Compiler argument for output file
SOURCES = main.c mongoose.c       # Source code files

# CFLAGS for compilation - should be simple for an MSVCRT-targeting toolchain
CFLAGS = -W -Wall -Wextra -g -I.

# Mongoose build options. See https://mongoose.ws/documentation/#build-options
CFLAGS_MONGOOSE += -DMG_HTTP_DIRLIST_TIME_FMT="%Y/%m/%d %H:%M:%S"
CFLAGS_MONGOOSE += -DMG_ENABLE_LINES=1 -DMG_ENABLE_IPV6=1 -DMG_ENABLE_SSI=1
# For this setup, we'll still disable Mongoose's built-in TLS via command line
# as it simplifies things and avoids potential crypto lib dependencies.
CFLAGS_EXTRA ?= "" # Default to no extra flags, expecting -DMG_TLS_DISABLED=1 from command line

ifeq ($(OS),Windows_NT)   # Windows settings
  PROG ?= http_server.exe       # Use .exe suffix for the binary
  CC = gcc                      # Should now point to your MSVCRT-MinGW gcc
  # Add Windows-specific libraries to CFLAGS so they are used during linking
  CFLAGS += -lws2_32 -lbcrypt
  DELETE = cmd /C del /Q /F /S
  OUT ?= -o $(PROG)
endif

all: $(PROG)
#	 No auto-run

$(PROG): $(SOURCES)       # Build program from sources
	$(CC) $(SOURCES) $(CFLAGS) $(CFLAGS_MONGOOSE) $(CFLAGS_EXTRA) $(OUT)

vc98:
	cl $(SOURCES) -DMG_ENABLE_SSI=1 # Example for MSVC, not relevant here

clean:                    # Cleanup
	$(DELETE) $(PROG) *.o *.obj *.exe *.dSYM