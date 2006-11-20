package Sniff;

import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
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
	private int deviceNumber;
	private int requestCount;
	private int responseCount;
	private JpcapCaptor jpcap;
	private ArrayList <RequestMessage> requestMessages;
	
	public Sniffer(int device) {
		this.requestCount = 0;
		this.responseCount = 0;
		this.deviceNumber = device;
		this.requestMessages = new ArrayList <RequestMessage> (REQUEST_LIMIT);
	}

	public void start() {
		try {
			NetworkInterface[] devices = JpcapCaptor.getDeviceList();
			System.out.println("Device: " + devices[deviceNumber].description);
			jpcap = JpcapCaptor.openDevice(devices[deviceNumber], 2000, false, 20);
			jpcap.setFilter("tcp", true);
			jpcap.loopPacket(-1, new Sniffer(deviceNumber));
		}
		
		catch (IOException e) {
			System.out.println("[E] ---");
		}
	}
	
	public void receivePacket(Packet packet) {
		if(requestCount >= REQUEST_LIMIT && requestMessages.isEmpty()) {
			System.exit(0);
		}
//		System.out.println("> " + packet.toString());
		extractInformation(packet);
		System.out.println("---------" + requestCount + "----------");
	}

	private String writeMetadata(RequestMessage req, ResponseMessage res) {
		String folderName;
		String parameters[] = {};
		
		if(req.getHeaders().split("\\s")[1].contains("?")) {
			folderName = req.getHeaders().split("\\s")[0] + "_"
			+ req.getDst_ip() + "_"
			+ req.getHeaders().split("\\s")[1].split("\\?")[0] + "_"
			+ req.getTimestamp();
			
			parameters = req.getHeaders().split("\\s")[1].split("\\?")[1].split("\\&");
		}
		
		else {
			folderName = req.getHeaders().split("\\s")[0] + "_"
			+ req.getDst_ip() + "_"
			+ req.getHeaders().split("\\s")[1] + "_"
			+ req.getTimestamp();
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
				uri = req.getHeaders().split("\\s")[1].split("\\?")[0];
			}

			else {
				uri = req.getHeaders().split("\\s")[1];
			}

			String headLine = "REQUEST "
				+ req.getHeaders().split("\\s")[2] + " "
				+ req.getHeaders().split("\\s")[0] + " "
				+ uri + " "
				+ req.getSrc_ip() + " "
				+ req.getSrc_port() + " "
				+ req.getDst_ip() + " "
				+ req.getDst_port();

			bw.write(headLine);
			bw.newLine();
			String headRequests[] = req.getHeaders().split("\\|")[1].split("\\[NEWLINE\\]");
			int index;
			for(index = 0; index < headRequests.length; index++) {
				bw.write(headRequests[index]);
				bw.newLine();
			}

			for(index = 0; index < parameters.length; index++) {
				bw.write(parameters[index]);
				bw.newLine();
			}
			
			// new line
			bw.newLine();

			// write response
			headLine = "RESPONSE "
				+ res.getHeaders().split("\\s")[0] + " "
				+ res.getHeaders().split("\\s")[1] + " "
				+ res.getSrc_ip() + " "
				+ res.getSrc_port() + " "
				+ res.getDst_ip() + " "
				+ res.getDst_port();

			bw.write(headLine);
			bw.newLine();
			
			headRequests = res.getHeaders().split("\\|")[1].split("\\[NEWLINE\\]");
			for(index = 0; index < headRequests.length; index++) {
				bw.write(headRequests[index]);
				bw.newLine();
			}
			
			bw.close();
			
			return folderName;
		}

		catch (IOException e) {
			System.out.println("[E] ---");
			return null;
		}
	}
	
	private void extractInformation(Packet packet) {
		/**
		 * segment of code including the BufferedReader related operations are
		 * inspired by the JpcapDumper (http://netresearch.ics.uci.edu/kfujii/jpcapdumper)
		 */
		// holds the whole message in an array
		String message = "";
		
		// double-checking -- "tcp" filter guarantees that anyway
		if(packet instanceof TCPPacket) {
			TCPPacket tempPacket = (TCPPacket) packet;
			int byteCount;
			
			try {
				BufferedReader br = new BufferedReader(new StringReader(new String(packet.data)));
				String temp = br.readLine();
				message = message + temp + " |";
				
				if(temp == null || !temp.contains("HTTP")) {
					byteCount = 0;
					while(temp != null) {
						System.out.println("[" + temp.getBytes().length + "]" + temp);
						byteCount += temp.getBytes().length;
						temp = br.readLine();
					}
					
					System.out.println("TCP > " + tempPacket.sequence + " | " + byteCount);
					
					return;
				}
				
				// read the application layer information (HTTP-related)
				// if request push into the request array
				if(checkIfRequest(temp) && requestCount < REQUEST_LIMIT) {
					requestCount++;
//					System.out.println("> " + temp);
					while((temp = br.readLine()).length() > 0) {
//						System.out.println("> " + temp);
						message = message + temp + "[NEWLINE]";
					}
					
					System.out.println("HTTP REQ > " + tempPacket.sequence);
					
					message = message.trim();
					requestMessages.add(new RequestMessage(tempPacket.src_ip.getHostAddress(), tempPacket.src_port, tempPacket.dst_ip.getHostAddress(), tempPacket.dst_port, java.lang.System.currentTimeMillis(), message));
				}
				
				// else push into the response array
				else if(checkifResponse(temp)) {
					RequestMessage matchingRequest = responseExpected(tempPacket);
					
					if(matchingRequest != null) {
//						System.out.println("> " + temp);
						System.out.println("[" + temp.getBytes().length + "]" + temp);
						while((temp = br.readLine()).length() > 0) {
//							System.out.println("> " + temp);
							System.out.println("[" + temp.getBytes().length + "]" + temp);
							message = message + temp + "[NEWLINE]";
						}
						
						temp = br.readLine();
						
						// data starts here
						byteCount = 0;
						ArrayList <byte[]> byteList = new ArrayList <byte[]> ();
						
						while(temp != null) {
							System.out.println("[" + temp.getBytes().length + "]" + temp);
							byteCount += temp.getBytes().length;
							byteList.add(temp.getBytes());
							temp = br.readLine();
//							System.out.println(">>>>>>" + data.length);
						}
						
						System.out.println("HTTP RES > " + tempPacket.sequence + " | " + byteCount);

						message = message.trim();						
						writeData(byteList, writeMetadata(matchingRequest, new ResponseMessage(tempPacket.dst_ip.getHostAddress(), tempPacket.dst_port, tempPacket.src_ip.getHostAddress(), tempPacket.src_port, message)));
						requestMessages.remove(matchingRequest);
					}
				}
			}
			
			catch (IOException e) {
				System.out.println("[E] Failed to parse the TCP packet.");
			}
		}
	}

	private void writeData(ArrayList <byte[]> byteList, String folder) {
		// write the data			
		try {
			FileOutputStream fo = new FileOutputStream(new File(folder + File.separator + "data"));
			DataOutputStream dos = new DataOutputStream(fo);
			
			int count;
			for(count = 0; count < byteList.size(); count++) {
				dos.write(byteList.get(count));
			}
			
			dos.close();
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		

			
		
	}

	private RequestMessage responseExpected(TCPPacket tempPacket) {
		int count;		
		for(count = 0; count < requestMessages.size(); count++) {
			String src_ip = requestMessages.get(count).getSrc_ip();
			String src_port = Integer.toString(requestMessages.get(count).getSrc_port());
			String dst_ip = requestMessages.get(count).getDst_ip();
			String dst_port = Integer.toString(requestMessages.get(count).getDst_port());
			
//			System.out.println("." + src_ip + ".=." + tempPacket.dst_ip.getHostAddress() + ".");
//			System.out.println("." + src_port + ".=." + tempPacket.dst_port + ".");
//			System.out.println("." + dst_ip + ".=." + tempPacket.src_ip.getHostAddress() + ".");
//			System.out.println("." + dst_port + ".=." + tempPacket.src_port + ".");
			
			if(src_ip.equals(tempPacket.dst_ip.getHostAddress())
					&& src_port.equals(Integer.toString(tempPacket.dst_port))
					&& dst_ip.equals(tempPacket.src_ip.getHostAddress())
					&& dst_port.equals(Integer.toString(tempPacket.src_port))) {
				
//				if(responseCount == 10 && responseCount == requestCount) {
//					doneCapturing = true;
//				}
				return requestMessages.get(count);
			}
		}
		
		return null;
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
		}
		
		return result;
	}
}
