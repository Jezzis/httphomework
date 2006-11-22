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
	private static final int LF_LENGTH = new String("\n").getBytes().length;
	private static final int CR_LENGTH = LF_LENGTH;
	private int deviceNumber;
	private int requestCount;
	private int responseCount;
	private JpcapCaptor jpcap;
	private ArrayList <RequestMessage> requestMessages;
	private ArrayList <RequestMessage> incompleteRequestMessages;
	private ArrayList <ResponseMessage> responseMessages;

	public Sniffer(int device) {
		this.requestCount = 0;
		this.responseCount = 0;
		this.deviceNumber = device;
		this.requestMessages = new ArrayList <RequestMessage> (REQUEST_LIMIT);
		this.incompleteRequestMessages = new ArrayList <RequestMessage> (REQUEST_LIMIT);
		this.responseMessages = new ArrayList <ResponseMessage> (REQUEST_LIMIT);
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
		if(requestCount > REQUEST_LIMIT && incompleteRequestMessages.isEmpty()) {
			System.exit(0);
		}
//		System.out.println("> " + packet.toString());
		extractInformation(packet);
		System.out.println("---------" + requestCount + "----------");
	}

	private String createFolder(RequestMessage req){
		String folderName;
		String parameters[] = {};
		
		if(req.getHeaders().split("\\s")[1].contains("?")) {
			folderName = req.getHeaders().split("\\s")[0] + "_"
			+ req.getDst_ip() + "_"
			+ req.getHeaders().split("\\s")[1].split("\\?")[0] + "_"
			+ req.getTimestamp();
			
			parameters = req.getHeaders().split("\\s")[1].split("\\?")[1].split("\\&");
			System.out.println(">> " + folderName);
		}
		
		else {
			folderName = req.getHeaders().split("\\s")[0] + "_"
			+ req.getDst_ip() + "_"
			+ req.getHeaders().split("\\s")[1] + "_"
			+ req.getTimestamp();
		}
		System.out.println(">> " + folderName);
		
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
		
		return folderName;
		
	}

	private String writeMetadata(RequestMessage req, ResponseMessage res, String folderName) {
		String parameters [] = {};
		if(req.getHeaders().contains("?")){
			parameters = req.getHeaders().split("\\s")[1].split("\\?")[1].split("\\&");
		}
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
				+ res.getDst_port() + " "
				+ res.getSegmentCount();

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
			int contentLength = 0;
			
			try {
				BufferedReader br = new BufferedReader(new StringReader(new String(packet.data)));
				String temp = br.readLine();
				message = message + temp + " |";
				
				if(temp == null || !temp.contains("HTTP")) {
					byteCount = 0;
//					while(temp != null) {
//						System.out.println("[" + temp.getBytes().length + "]" + temp);
//						byteCount += temp.getBytes().length + LF_LENGTH + CR_LENGTH;
//						temp = br.readLine();
//					}
//					
//					byteCount--;
					
					System.out.println("TCP > length:" + tempPacket.data.length + " | seq: " + tempPacket.sequence + " | ack: " + tempPacket.ack_num);

					for(int i = 0; i < responseMessages.size(); i++){
						//System.out.println(">>>response src: "+responseMessages.get(i).getSrc_port());
						//System.out.println(">>>temp src: "+tempPacket.src_port);
						//System.out.println(">>>response dst: "+responseMessages.get(i).getDst_port());
						//System.out.println(">>>temp dst: "+tempPacket.dst_port);
						if(responseMessages.get(i).getSrc_port() == tempPacket.dst_port
								&& responseMessages.get(i).getDst_port() == tempPacket.src_port){
							responseMessages.get(i).setReceivedContentLength(responseMessages.get(i).getReceivedContentLength() + tempPacket.data.length);
							System.out.println(">>>Received Content Length:" + responseMessages.get(i).getReceivedContentLength());
							System.out.println(">>>Content Length:" + responseMessages.get(i).getContentLength());
//							writeData(tempPacket.data, 0, tempPacket.data.length-1, requestMessages.get(responseMessages.get(i).getMatchingRequestMessageIndex()).getFolderName() );
							if(responseMessages.get(i).getReceivedContentLength() == responseMessages.get(i).getContentLength()){
								responseMessages.get(i).setSegmentCount(responseMessages.get(i).getSegmentCount()+1);
								//isComplete?
								//responseMessages.get(i).setComplete(true); 
								System.out.println(">>> Segment Count: " + responseMessages.get(i).getSegmentCount());
								System.out.println(">>> Folder Name: " + requestMessages.get(responseMessages.get(i).getMatchingRequestMessageIndex()).getFolderName());
//								writeMetadata(requestMessages.get(responseMessages.get(i).getMatchingRequestMessageIndex()), responseMessages.get(i), requestMessages.get(responseMessages.get(i).getMatchingRequestMessageIndex()).getFolderName());
								requestMessages.remove(responseMessages.get(i).getMatchingRequestMessageIndex());
								responseMessages.remove(i);
								break;
							}
							
							else{
								//if(!responseMessages.get(i).isComplete()){
								responseMessages.get(i).setSegmentCount(responseMessages.get(i).getSegmentCount()+1);
								//writeData
							}
						}
					}

					return;
				}
				
				// read the application layer information (HTTP-related)
				// if request push into the request array
				if(checkIfRequest(temp) && requestCount <= REQUEST_LIMIT) {
					requestCount++;
					while((temp = br.readLine()).length() > 0) {
						message = message + temp + "[NEWLINE]";
					}
					
					System.out.println("HTTP REQ > seq: " + tempPacket.sequence + " | ack: " + tempPacket.ack_num);
					
					message = message.trim();
					RequestMessage req = new RequestMessage(tempPacket.src_ip.getHostAddress(), tempPacket.src_port, tempPacket.dst_ip.getHostAddress(), tempPacket.dst_port, java.lang.System.currentTimeMillis(), message, tempPacket.sequence + tempPacket.data.length);
					req.setFolderName(createFolder(req));
					incompleteRequestMessages.add(req);
				}
				
				// else push into the response array
				else if(checkifResponse(temp)) {
					RequestMessage matchingRequest = responseExpected(tempPacket);
					byteCount = 0;
					byteCount += temp.getBytes().length + LF_LENGTH + CR_LENGTH;
					if(matchingRequest != null) {
						System.out.println("[" + temp.getBytes().length + "]" + temp);
						while((temp = br.readLine()).length() > 0) {
							if(temp.startsWith("Content-Length:"))
							{
								contentLength = Integer.parseInt(temp.split(": ")[1]);
							}
							byteCount += temp.getBytes().length + LF_LENGTH + CR_LENGTH;
							System.out.println("[" + temp.getBytes().length + "]" + temp);
							message = message + temp + "[NEWLINE]";
						}

						System.out.println(">" + temp + "<");
						byteCount += LF_LENGTH + CR_LENGTH;
//						System.out.println(">>>" + byteCount);
//						temp = br.readLine();
//						System.out.println(">" + temp + "<");
						
						// data starts here
//						byteCount = 0;
//						ArrayList <byte[]> byteList = new ArrayList <byte[]> ();
//						
//						while(temp != null) {
//							System.out.println("[" + temp.getBytes().length + "]" + temp);
//							byteCount += temp.getBytes().length + LF_LENGTH + CR_LENGTH;
//							byteList.add(temp.getBytes());
//							temp = br.readLine();
//						}
						
						System.out.println("HTTP REQ > seq: " + tempPacket.sequence + " | ack: " + tempPacket.ack_num);

						message = message.trim();
						responseMessages.add(new ResponseMessage(tempPacket.dst_ip.getHostAddress(), tempPacket.dst_port, tempPacket.src_ip.getHostAddress(), tempPacket.src_port, message, contentLength, tempPacket.data.length - byteCount));
						
						
						for(int i = 0; i < incompleteRequestMessages.size(); i++){
							if(incompleteRequestMessages.get(i).getSrc_port() == tempPacket.dst_port
									&& incompleteRequestMessages.get(i).getDst_port() == tempPacket.src_port){
								writeData(tempPacket.data, byteCount, tempPacket.data.length - byteCount, incompleteRequestMessages.get(i).getFolderName());
							}
						}
						
						incompleteRequestMessages.remove(matchingRequest);
						
						/*
						if(responseMessages.get(responseMessages.size()-1).getContentLength() <= tempPacket.data.length - byteCount)
							writeMetadata(requestMessages.get(responseMessages.get(responseMessages.size()-1).getMatchingRequestMessageIndex()), responseMessages.get(responseMessages.size()-1));
						else{
						*/
							requestMessages.add(matchingRequest);
							responseMessages.get(responseMessages.size()-1).setMatchingRequestMessageIndex(requestMessages.indexOf(matchingRequest));	
						//}
						
						
						}
					}
				
			
			}
			catch (IOException e) {
				System.out.println("[E] Failed to parse the TCP packet.");
			}
		}
	}

	private void writeData(byte[] data, int offset, int length, String folder) {
		// write the data			
		try {
			// append data to the file
			FileOutputStream fo = new FileOutputStream(new File(folder + File.separator + "data"), true);
			DataOutputStream dos = new DataOutputStream(fo);
			//dos.write(data);
			dos.write(data, offset, length);
			
			/*
			int count;
			for(count = 0; count < byteList.size(); count++) {
				dos.write(byteList.get(count));
			}
			*/
			dos.close();
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private RequestMessage responseExpected(TCPPacket tempPacket) {
		int count;		
		for(count = 0; count < incompleteRequestMessages.size(); count++) {
			String src_ip = incompleteRequestMessages.get(count).getSrc_ip();
			String src_port = Integer.toString(incompleteRequestMessages.get(count).getSrc_port());
			String dst_ip = incompleteRequestMessages.get(count).getDst_ip();
			String dst_port = Integer.toString(incompleteRequestMessages.get(count).getDst_port());
			
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
				return incompleteRequestMessages.get(count);
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
