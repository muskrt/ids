import psutil 
import time
import sys

def network_activity():
    old_value = old_value2 = 0
    while True:
        new_value = psutil.net_io_counters().bytes_recv
        new_value2 = psutil.net_io_counters().bytes_sent

        if old_value:
            rx = round((new_value - old_value) / 1024.0, 2)
            tx = round((new_value2 - old_value2) / 1024.0, 2)
            rx_tx = round(((new_value - old_value + new_value2 - old_value2) / 1024.0)*8,2)
            # print('\rrx_tx: {}'.format(rx_tx),flush=True,end='')
            return rx_tx
            
        old_value = new_value
        old_value2 = new_value2
        time.sleep(1)

    