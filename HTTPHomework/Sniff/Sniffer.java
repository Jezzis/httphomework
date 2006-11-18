package Sniff;

import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;

public class Sniffer implements PacketReceiver {
	private static final int REQUEST_LIMIT = 10;
	private static final int RESPONSE_LIMIT = 10;
	private int deviceNumber;
	private int requestCount;
	private int responseCount;
	private JpcapCaptor jpcap;
	private ArrayList <String> requestMessages;
	private ArrayList <String> responseMessages;
	private ArrayList <String> requestMessageAddresses;
	private ArrayList <String> responseMessageAddresses;
	private ArrayList <String> requestMessageTimestamps;
	private boolean doneCapturing;
	
	public Sniffer(int device) {
		this.requestCount = 0;
		this.responseCount = 0;
		this.deviceNumber = device;
		this.requestMessages = new ArrayList <String> (REQUEST_LIMIT);
		this.responseMessages = new ArrayList <String> (RESPONSE_LIMIT);
		this.requestMessageAddresses = new ArrayList <String> (REQUEST_LIMIT);
		this.responseMessageAddresses = new ArrayList <String> (RESPONSE_LIMIT);
		this.requestMessageTimestamps = new ArrayList <String> (REQUEST_LIMIT);
		this.doneCapturing = false;
	}

	public void start() {
		try {
			NetworkInterface[] devices = JpcapCaptor.getDeviceList();
			System.out.println("Device: " + devices[deviceNumber].description);
			jpcap = JpcapCaptor.openDevice(devices[deviceNumber], 2000, false, 20);
			jpcap.setFilter("http", true);
			jpcap.loopPacket(-1, new Sniffer(deviceNumber));
		}
		
		catch (IOException e) {
			System.out.println("[E] ---");
		}
	}
	
	public void receivePacket(Packet packet) {
		if(doneCapturing) {
			writeMetadata();
			System.exit(0);
		}
		
		extractInformation(packet);
		System.out.println("---------" + requestCount + "----------");
	}

	private void writeMetadata() {
		int count;
		String folderName;
		String parameters[] = {};
		
		for(count = 0; count < requestMessages.size(); count++) {
			// create the folder for the request/response pair
			if(requestMessages.get(count).split("\\s")[1].contains("?")) {
				folderName = requestMessages.get(count).split("\\s")[0] + "_"
				+ requestMessageAddresses.get(count).split("\\s")[2] + "_"
				+ requestMessages.get(count).split("\\s")[1].split("\\?")[0] + "_"
				+ requestMessageTimestamps.get(count);
				
				parameters = requestMessages.get(count).split("\\s")[1].split("\\?")[1].split("\\&");
			}
			
			else {
				folderName = requestMessages.get(count).split("\\s")[0] + "_"
				+ requestMessageAddresses.get(count).split("\\s")[2] + "_"
				+ requestMessages.get(count).split("\\s")[1] + "_"
				+ requestMessageTimestamps.get(count);
			}
			
			folderName = folderName.replace("/", "-");
			folderName = folderName.replace("?", "-");
			folderName = folderName.replace("\\", "-");
			folderName = folderName.replace(":", "-");
			folderName = folderName.replace("*", "-");
			folderName = folderName.replace("\"", "-");
			folderName = folderName.replace("<", "-");
			folderName = folderName.replace(">", "-");
			folderName = folderName.replace("|", "-");
			
			System.out.println(">> " + folderName);
			new File(folderName).mkdir();
			
			// write the request/response information
			try {				
				FileWriter fw = new FileWriter(folderName + File.separator + "metadata.txt");
				BufferedWriter bw = new BufferedWriter(fw);
				
				// write request
				String uri = "";
				if(parameters.length > 0) {
					uri = requestMessages.get(count).split("\\s")[1].split("\\?")[0];
				}
				
				else {
					uri = requestMessages.get(count).split("\\s")[1];
				}
				
				String headLine = "REQUEST "
									+ requestMessages.get(count).split("\\s")[2] + " "
									+ requestMessages.get(count).split("\\s")[0] + " "
									+ uri + " "
									+ requestMessageAddresses.get(count).split("\\s")[0] + " "
									+ requestMessageAddresses.get(count).split("\\s")[1] + " "
									+ requestMessageAddresses.get(count).split("\\s")[2] + " "
									+ requestMessageAddresses.get(count).split("\\s")[3];
				
				bw.write(headLine);
				bw.newLine();
				String headRequests[] = requestMessages.get(count).split("\\|")[1].split("\\[NEWLINE\\]");
				int index;
				for(index = 0; index < headRequests.length; index++) {
					bw.write(headRequests[index]);
					bw.newLine();
				}
				
				for(index = 0; index < parameters.length; index++) {
					bw.write(parameters[index]);
					bw.newLine();
				}
				
				// write response
				headLine = "RESPONSE "
							+ responseMessages.get(count).split("\\s")[0] + " "
							+ responseMessages.get(count).split("\\s")[1] + " "
							+ responseMessageAddresses.get(count).split("\\s")[0] + " "
							+ responseMessageAddresses.get(count).split("\\s")[1] + " "
							+ responseMessageAddresses.get(count).split("\\s")[2] + " "
							+ responseMessageAddresses.get(count).split("\\s")[3];
				
				bw.write(headLine);
				bw.newLine();
				bw.close();
			}
			
			catch (IOException e) {
				System.out.println("[E] ---");
			}
		}
		
	}

	private void extractInformation(Packet packet) {
		/**
		 * segment of code including the BufferedReader related operations are
		 * inspired by the JpcapDumper (http://netresearch.ics.uci.edu/kfujii/jpcapdumper)
		 */
		// holds the whole message in an array
		String message = "";
		
		// double-checking -- "http" filter guarantees that anyway
		if(packet instanceof TCPPacket) {
			TCPPacket tempPacket = (TCPPacket) packet;
			
			try {
				BufferedReader br = new BufferedReader(new StringReader(new String(packet.data)));
				String temp = br.readLine();
				message = message + temp + " |";
				
				if(temp == null || !temp.contains("HTTP")) {
					return;
				}
				
				// read the application layer information (HTTP-related)
				// if request push into the request array
				if(checkIfRequest(temp)) {
//					System.out.println("> " + temp);
					while((temp = br.readLine()).length() > 0) {
//						System.out.println("> " + temp);
						message = message + temp + "[NEWLINE]";
					}
					
					message = message.trim();
					requestMessages.add(message);
					requestMessageAddresses.add(tempPacket.src_ip.getHostAddress() + " " + tempPacket.src_port + " " + tempPacket.dst_ip.getHostAddress() + " " + tempPacket.dst_port);
					requestMessageTimestamps.add(java.lang.System.currentTimeMillis() + "");
				}
				
				// else push into the response array
				else if(checkifResponse(temp) && responseExpected(tempPacket)) {
//					System.out.println("> " + temp);
					while((temp = br.readLine()).length() > 0) {
//						System.out.println("> " + temp);
						message = message + temp + "[NEWLINE]";
					}
					
					message = message.trim();
					responseMessages.add(message);
					responseMessageAddresses.add(tempPacket.dst_ip.getHostAddress() + " " + tempPacket.dst_port + " " + tempPacket.src_ip.getHostAddress() + " " + tempPacket.src_port);
				}
			}
			
			catch (IOException e) {
				System.out.println("[E] Failed to parse the TCP packet.");
			}
		}
	}

	private boolean responseExpected(TCPPacket tempPacket) {
		int count;		
		for(count = 0; count < requestMessageAddresses.size(); count++) {
			String src_ip = requestMessageAddresses.get(count).split("\\s")[0];
			String src_port = requestMessageAddresses.get(count).split("\\s")[1];
			String dst_ip = requestMessageAddresses.get(count).split("\\s")[2];
			String dst_port = requestMessageAddresses.get(count).split("\\s")[3];
			
			System.out.println("." + src_ip + ".=." + tempPacket.dst_ip.getHostAddress() + ".");
			System.out.println("." + src_port + ".=." + tempPacket.dst_port + ".");
			System.out.println("." + dst_ip + ".=." + tempPacket.src_ip.getHostAddress() + ".");
			System.out.println("." + dst_port + ".=." + tempPacket.src_port + ".");
			
			if(src_ip.equals(tempPacket.dst_ip.getHostAddress())
					&& src_port.equals(Integer.toString(tempPacket.dst_port))
					&& dst_ip.equals(tempPacket.src_ip.getHostAddress())
					&& dst_port.equals(Integer.toString(tempPacket.src_port))) {
				
				if(responseCount == 10 && responseCount == requestCount) {
					doneCapturing = true;
				}
				
				return true;
			}
		}
		
		return false;
	}

	private boolean checkifResponse(String s) {
		/**
		 * the first line` of a response message is called the status-line.
		 * for more information see: http://web-sniffer.net/rfc/rfc2616.html#section-6.1
		 * ---
		 * Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
		 */
		boolean result = false;
		
		if(s.startsWith("HTTP/1.0") || s.startsWith("HTTP/1.1")) {
			result = true;
			responseCount++;
		}
		
		return result; 
	}

	private boolean checkIfRequest(String s) {
		boolean result = false;
		
		if(s.startsWith("GET") || s.startsWith("POST") || s.startsWith("HEAD")) {
			result = true;
			requestCount++;
		}
		
		return result;
	}
}
