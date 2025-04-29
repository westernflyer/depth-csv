#
# Copyright (c) 2025-present Tom Keffer <tkeffer@gmail.com>
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
#
"""Read depth, lat, lon from a socket, write to a file."""
from __future__ import annotations

import errno
import logging
import socket
import sys
import time
from datetime import datetime, timezone
from logging.handlers import SysLogHandler

import parse_nmea
from config import *

# Set up logging using the system logger
if sys.platform == "darwin":
    address = '/var/run/syslog'
else:
    address = '/dev/log'
log = logging.getLogger("depth-csv")
log.setLevel(logging.DEBUG if DEBUG else logging.INFO)
handler = SysLogHandler(address=address)
formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)


def main():
    log.info("Starting up depth-csv.  ")
    log.info("Debug level: %s", DEBUG)

    while True:
        try:
            nmea_loop()
        except KeyboardInterrupt:
            sys.exit("Keyboard interrupt. Exiting.")
        except ConnectionResetError as e:
            warn_print_sleep(f"Connection reset: {e}")
        except ConnectionRefusedError as e:
            warn_print_sleep(f"Connection refused: {e}")
        except TimeoutError as e:
            warn_print_sleep(f"Socket timeout: {e}")
        except socket.gaierror as e:
            warn_print_sleep(f"GAI error: {e}")
        except OSError as e:
            # Retry if it's a network unreachable error. Otherwise, reraise the exception.
            if e.errno == errno.ENETUNREACH or e.errno == errno.EHOSTUNREACH:
                warn_print_sleep(f"Network unreachable: {e}")
            else:
                raise


def nmea_loop():
    """Read sentences from a socket, parse, write depth, lat, lon to a CSV file.

    This is the heart of the program.
    """
    # Timestamp of the last write
    last_write = 0
    # Last known position
    last_position = None
    # Last value for the cumulative log
    last_log = None

    # Open the socket connection and start reading lines
    for line in gen_nmea(NMEA_HOST, NMEA_PORT):
        try:
            # Parse the line. Be prepared to catch any exceptions.
            parsed_nmea = parse_nmea.parse(line)
        except parse_nmea.UnknownNMEASentence as e:
            # We need GPT and GLL. Fail hard if not provided. Otherwise, press on.
            if e.sentence_type in {'DPT', 'GLL'}:
                raise
            else:
                continue
        except (parse_nmea.NMEAParsingError, parse_nmea.NMEAStatusError) as e:
            log.warning("NMEA error: %s", e)
            print(f"NMEA error: {e}", file=sys.stderr)
            continue
        else:
            # Parsing went ok.
            sentence_type = parsed_nmea["sentence_type"]
            if sentence_type == "GLL":
                # Save the position
                last_position = parsed_nmea
            elif sentence_type == "VLW":
                # Save the last distance log value
                last_log = parsed_nmea
            elif sentence_type == 'DPT':
                # Check whether enough time has elapsed
                delta = parsed_nmea["timestamp"] - last_write
                if delta >= WRITE_INTERVAL * 1000.0:
                    # Make sure the last position is fresh enough
                    if (last_position
                            and last_log
                            and parsed_nmea["timestamp"] - last_position["timestamp"] <= MAX_STALE * 1000.0):
                        write_depth(parsed_nmea["timestamp"],
                                    last_position["latitude"],
                                    last_position["longitude"],
                                    parsed_nmea.get("water_depth_meters"),
                                    last_log.get("water_total_nm"))
                        last_write = parsed_nmea["timestamp"]


def gen_nmea(host: str, port: int):
    """Listen for NMEA data on a TCP socket."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(NMEA_TIMEOUT)
        s.connect((host, port))
        log.info(f"Connected to NMEA socket at {host}:{port}; timeout: {NMEA_TIMEOUT} seconds.")
        with s.makefile('r') as nmea_stream:
            for line in nmea_stream:
                yield line.strip()


def write_depth(timestamp:str, latitude:str, longitude:str, depth:str, distance:str):
    """Write an entry to the CSV file"""
    epoch_time = int(timestamp)  # Parse the Unix epoch time (milliseconds)
    # Convert milliseconds to seconds and then to an ISO 8601 formatted UTC timestamp
    time_str = datetime.fromtimestamp(int(epoch_time / 1000 + 0.5), tz=timezone.utc).isoformat()
    lat_str = f"{latitude:.4f}" if latitude is not None else ""
    lon_str = f"{longitude:.4f}" if longitude is not None else ""
    depth_str = f"{depth:.1f}" if depth is not None else ""
    distance_str = f"{distance:.1f}" if distance is not None else ""
    with open(CSV_FILE, "a") as depth_file:
        depth_file.write(f"{timestamp:12.0f},{time_str},{lat_str},{lon_str},{depth_str},{distance_str}\n")


def warn_print_sleep(msg: str):
    """Print and log a warning message, then sleep for NMEA_RETRY_WAIT seconds."""
    print(msg, file=sys.stderr)
    print(f"*** Waiting {NMEA_RETRY_WAIT} seconds before retrying.", file=sys.stderr)
    log.warning(msg)
    log.warning(f"*** Waiting {NMEA_RETRY_WAIT} seconds before retrying.")
    time.sleep(NMEA_RETRY_WAIT)
    print("*** Retrying...", file=sys.stderr)
    log.warning("*** Retrying...")


if __name__ == "__main__":
    main()
