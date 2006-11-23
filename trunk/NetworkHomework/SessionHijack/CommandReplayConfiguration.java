package SessionHijack;
/**
 * nazli & alper
 */
public class CommandReplayConfiguration {
	private String applicationURL;
	private String sessionCookieName;
	private String requestParameterName;
	private String requestParameterValue;
	
	public CommandReplayConfiguration() {
		super();
	}
	
	public CommandReplayConfiguration(String applicationURL, String sessionCookieName, String requestParameterName, String requestParameterValue) {
		super();
		this.applicationURL = applicationURL;
		this.sessionCookieName = sessionCookieName;
		this.requestParameterName = requestParameterName;
		this.requestParameterValue = requestParameterValue;
	}

	public String getApplicationURL() {
		return applicationURL;
	}
	
	public void setApplicationURL(String applicationURL) {
		this.applicationURL = applicationURL;
	}
	
	public String getRequestParameterName() {
		return requestParameterName;
	}
	
	public void setRequestParameterName(String requestParameterName) {
		this.requestParameterName = requestParameterName;
	}
	
	public String getRequestParameterValue() {
		return requestParameterValue;
	}
	
	public void setRequestParameterValue(String requestParameterValue) {
		this.requestParameterValue = requestParameterValue;
	}
	
	public String getSessionCookieName() {
		return sessionCookieName;
	}
	
	public void setSessionCookieName(String sessionCookieName) {
		this.sessionCookieName = sessionCookieName;
	}
	
	public String toString() {
		return "app-url=" + this.getApplicationURL() + "\n"
			+ "session-cookie-name=" + this.getSessionCookieName() + "\n"
			+ "req-param-name=" + this.getRequestParameterName() + "\n"
			+ "req-param-value=" + this.getRequestParameterValue();
	}
}
