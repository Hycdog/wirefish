A graphical user interface for scapy.

### Start the application
Install the python3 packages listed in [requirements.txt](./requirements.txt). <br>
On Windows Platform:<br>
`python main.py`

On Linux Platform, sniffing packets requires root privilege.<br>
`$ sudo python3 main.py`

### How does it work
#### Select a network interface
In order to capture packets, first of all, we need to get the info about the network interfaces that we want to listen.
Using scapy, for example, we only need to do this:<br>
`>>> from scapy.all import *`<br> 
`>>> show_interfaces()`<br>

#### Start capturing
After we get the IFACE name, we do:<br>
`sniff(iface=`*Name of the interface*`, count=0)`

count=0 means scapy will keep capturing packets.

#### Decode packets
We can also pass the `sniff()` function the `callback` argument, denoted by `prn`<br>
`sniff(prn=self.showpkt, iface=self.iface, count=0)`<br>
After each successful sniffing, the `sniff()` function will call the callback function`self.showpkt()`,passing the captured packet `pkt` as the only argument.
Then, we expand the packet, turn it into a list of tuples, each contains part of the data contained in the packet.

#### Multitasking
Python3 does not truly support multithreading. However, PyQt does,  due to its backend written in C/C++, so we just run a main thread that interact with the user, while capturing the packets using another thread in the background.

<br>

##### TODO
Filter parser instead of multiple ComboBoxes.<br>
Move all decoding job to main thread.

