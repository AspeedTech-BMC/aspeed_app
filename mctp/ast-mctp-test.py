# open two uart serial port with pyserial module baud rate=115200 
# send cmd to port 1 and check response of port 2

import serial
import time
import random


MCTP_TX_PORT = 'COM1'
MCTP_RX_PORT = 'COM4'

MCTP_TX_BASE_CMD = 'mctp-ast -n /dev/aspeed-mctp1 -t'
MCTP_RX_BASE_CMD = 'mctp-ast -n /dev/aspeed-mctp0 -r -c 0'

def test_uart():
    # Open the first serial port (port 1)
    ser1 = serial.Serial(MCTP_TX_PORT, baudrate=115200, timeout=1)
    # Open the second serial port (port 2)
    ser2 = serial.Serial(MCTP_RX_PORT, baudrate=115200, timeout=1)
    test_trials = 1

    mctp_rx_cmd = MCTP_RX_BASE_CMD + '\r\n'
    ser2.write(mctp_rx_cmd.encode('utf-8'))
    while True:
        # Wait for the ports to open
        time.sleep(2)
        # Send a command to the first port
        mctp_tx_cmd = MCTP_TX_BASE_CMD
        mctp_tx_cmd += f' -i {random.randint(0, 255)}'
        mctp_tx_cmd += f' -b {random.randint(0, 255)}'
        mctp_tx_cmd += f' -d {random.randint(0, 31)}'
        mctp_tx_cmd += f' -f {random.randint(0, 7)}'
        mctp_tx_cmd += f' -o {random.choice([0, 2, 3])}'
        mctp_tx_cmd += f' -l {random.randint(17, 1000)}'
        # mctp_tx_cmd += f' -s {random.randint(0, 1)}'
        # mctp_tx_cmd += f' -e {random.randint(0, 1)}'

        print("Start trial:", test_trials)
        print("Sending command to port 1:", mctp_tx_cmd)
        mctp_tx_cmd += '\r\n'
        ser1.write(mctp_tx_cmd.encode('utf-8'))
        time.sleep(2)
        # Read the response from the second port
        raw_response = ser2.readlines()
        raw_response = [line.decode('utf-8').strip() for line in raw_response]
        passed = False
        for rsp in raw_response:
            if rsp.find('PASS') != -1:
                passed = True
                break
        if passed:
            print(f"Trial {test_trials} PASSED")
        else:
            print(f"Trial {test_trials} Failed")
            print(raw_response)
            break
        # Print the response
        print("Response from port 2:", raw_response)
        test_trials += 1
        # Close the serial ports
    ser1.close()
    ser2.close()

if __name__ == "__main__":
    test_uart()