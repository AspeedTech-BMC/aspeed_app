# AST MCTP UART Test

`ast-mctp-test.py` is a host-side stress-test script for the ASPEED MCTP over
PCIe test application. It controls two target systems through separate UART
consoles:

- the RX console runs `mctp-ast` continuously on `/dev/aspeed-mctp0`;
- the TX console sends randomized transfers through `/dev/aspeed-mctp1`;
- each trial passes when the RX console prints a line containing `PASS`.

The script continues until a trial does not produce `PASS`.

## Requirements

- Python 3
- [pySerial](https://pyserial.readthedocs.io/)
- Two UART serial ports connected to the TX and RX target consoles
- `mctp-ast` installed and available in the command search path on both targets
- The ASPEED MCTP driver and the configured device nodes available on the
  targets

Install the Python dependency with:

```sh
python3 -m pip install pyserial
```

The local `mctp-ast` utility can be built for the target architecture with the
repository Makefile. For example:

```sh
make CROSS_COMPILE=aarch64-linux-gnu-
```

Copy the resulting `mctp-ast` binary to each target and ensure it can be invoked
from its shell without specifying a path.

## Configuration

The script does not accept command-line options. Edit these constants near the
top of `ast-mctp-test.py` before running it:

```python
MCTP_TX_PORT = 'COM1'
MCTP_RX_PORT = 'COM4'

MCTP_TX_BASE_CMD = 'mctp-ast -n /dev/aspeed-mctp1 -t'
MCTP_RX_BASE_CMD = 'mctp-ast -n /dev/aspeed-mctp0 -r -c 0'
```

`MCTP_TX_PORT` and `MCTP_RX_PORT` are pySerial port names. Typical names are
`COM1` on Windows and `/dev/ttyUSB0` or `/dev/ttyACM0` on Linux. Confirm that
the selected UARTs are not already open in another terminal program.

Both UART consoles must already be at a shell prompt. The serial settings are
fixed at 115200 baud with a one-second read timeout.

The default RX command uses `-c 0`, which keeps `mctp-ast` receiving in a loop.
Change the device-node paths in the base commands if the targets expose
different ASPEED MCTP instances.

## Run the test

From this directory, run:

```sh
python3 ast-mctp-test.py
```

The script first sends the RX command, then generates one TX command per trial.
The following parameters are randomized:

| Option | Value range | Meaning |
| --- | --- | --- |
| `-i` | 0-255 | Destination endpoint ID |
| `-b` | 0-255 | Destination PCIe bus number |
| `-d` | 0-31 | Destination PCIe device number |
| `-f` | 0-7 | Destination PCIe function number |
| `-o` | 0, 2, or 3 | PCIe routing type |
| `-l` | 17-1000 | Transfer length in bytes |

Start-of-message (`-s`) and end-of-message (`-e`) randomization is present in
the source but disabled by default.

Example output:

```text
Start trial: 1
Sending command to port 1: mctp-ast -n /dev/aspeed-mctp1 -t -i 8 -b 3 -d 0 -f 0 -o 2 -l 256
Trial 1 PASSED
Response from port 2: [..., 'PASS']
```

On failure, the script prints all lines read from the RX console and stops:

```text
Trial 4 Failed
['...']
```

Press `Ctrl-C` to stop a running test. If necessary, send an interrupt to the
RX target afterward because its `mctp-ast -r -c 0` command runs continuously.

## Troubleshooting

- **The serial port cannot be opened:** verify the port names, permissions, and
  that no terminal emulator is using either port. On Linux, access may require
  membership in the system's serial-port group.
- **Every trial fails with an empty response:** confirm the TX and RX ports are
  assigned to the intended targets, both consoles were at a shell prompt, and
  increase the two-second waits in the script for a slower target.
- **`mctp-ast` is not found:** install the binary in the target's command search
  path or place its absolute path in the TX and RX base commands.
- **The MCTP device cannot be opened:** verify that the ASPEED MCTP kernel driver
  is loaded and that `/dev/aspeed-mctp0` and `/dev/aspeed-mctp1` match the target
  configuration.
- **Valid traffic is reported as failed:** the success check is case-sensitive
  and specifically looks for the text `PASS` in the RX UART output.

> **Note:** This test generates arbitrary endpoint IDs and PCIe BDF values.
> Run it only in a dedicated validation environment where randomized MCTP
> traffic is expected.
