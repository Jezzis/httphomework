package Sniff;

public class ResponseMessage {
	private String src_ip;
	private String dst_ip;
	private int src_port;
	private int dst_port;
	private String headers;
	private int matchingRequestMessageIndex;
	private int segmentCount;
	private int contentLength;
	private int receivedContentLength;
	
	public ResponseMessage(String src_ip, int src_port, String dst_ip, int dst_port, String headers, int length, int receivedLength) {
		this.src_ip = src_ip;
		this.dst_ip = dst_ip;
		this.src_port = src_port;
		this.dst_port = dst_port;
		this.headers = headers;
		this.matchingRequestMessageIndex = -1;
		this.segmentCount = 1;
		this.receivedContentLength = receivedLength;
		this.contentLength = length;
	}

	public String getDst_ip() {
		return dst_ip;
	}

	public void setDst_ip(String dst_ip) {
		this.dst_ip = dst_ip;
	}

	public int getDst_port() {
		return dst_port;
	}

	public void setDst_port(int dst_port) {
		this.dst_port = dst_port;
	}

	public String getHeaders() {
		return headers;
	}

	public void setHeaders(String headers) {
		this.headers = headers;
	}

	public String getSrc_ip() {
		return src_ip;
	}

	public void setSrc_ip(String src_ip) {
		this.src_ip = src_ip;
	}

	public int getSrc_port() {
		return src_port;
	}

	public void setSrc_port(int src_port) {
		this.src_port = src_port;
	}

	public int getMatchingRequestMessageIndex() {
		return matchingRequestMessageIndex;
	}

	public void setMatchingRequestMessageIndex(int matchingRequestMessageIndex) {
		this.matchingRequestMessageIndex = matchingRequestMessageIndex;
	}

	public int getSegmentCount() {
		return segmentCount;
	}

	public void setSegmentCount(int segmentCount) {
		this.segmentCount = segmentCount;
	}

	public int getReceivedContentLength() {
		return receivedContentLength;
	}

	public void setReceivedContentLength(int receivedContentLength) {
		this.receivedContentLength = receivedContentLength;
	}

	public int getContentLength() {
		return contentLength;
	}

	public void setContentLength(int contentLength) {
		this.contentLength = contentLength;
	}	
}
