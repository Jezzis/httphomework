package Sniff;

import java.io.IOException;

import jpcap.*;
import jpcap.packet.Packet;

public class Sniffer implements PacketReceiver {
	private int deviceNumber;
	
	public Sniffer(int device) {
		this.deviceNumber = device;
	}

	public void start() {
		try {
			NetworkInterface[] devices = JpcapCaptor.getDeviceList();
			JpcapCaptor jpcap;
			jpcap = JpcapCaptor.openDevice(devices[deviceNumber], 2000, false, 20);
			String localAddress = devices[deviceNumber].addresses[0].address.toString();
			jpcap.setFilter("src host " + localAddress, true);
			jpcap.loopPacket(-1, new Sniffer(deviceNumber));
		}
		
		catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void receivePacket(Packet packet) {
		System.out.println(packet);
	}
}
