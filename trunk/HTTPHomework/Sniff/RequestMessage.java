package Sniff;

public class RequestMessage {
	private String src_ip;
	private String dst_ip;
	private int src_port;
	private int dst_port;
	private long timestamp;
	private String headers;
	
	public RequestMessage(String src_ip, int src_port, String dst_ip, int dst_port, long timestamp, String headers) {
		this.src_ip = src_ip;
		this.dst_ip = dst_ip;
		this.src_port = src_port;
		this.dst_port = dst_port;
		this.timestamp = timestamp;
		this.headers = headers;
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

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}
	
	

}
