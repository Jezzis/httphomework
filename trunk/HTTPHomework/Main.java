import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import Sniff.Sniffer;

/**
 * nazli & alper
 */
public class Main {
	// name of the configuration file resising in the same directory as this class
	public static final String configurationFileName = "replay-config.txt";
	
	// configuration object
	private static CommandReplayConfiguration crc;

	/**
	 * @param args N/A
	 */
	public static void main(String[] args) throws IOException {
		// read the configuration file and store the contents in an object
		readConfiguration();
		
		System.out.println(crc);
		
		// why 1? because my wireless card is the second (index = 1) device according to jpcap
		Sniffer s = new Sniffer(1);
		s.start();
	}

	/**
	 * read the configuration file and store the contents in a CommandReplayConfiguration object
	 * assuming that the configuration file is written correctly (format, etc.)
	 *
	 */
	private static void readConfiguration() {
		// open the file and read it
		try {
			FileReader fr = new FileReader(configurationFileName);
			BufferedReader br = new BufferedReader(fr);
			
			// we know the format of the configuration file -- 4 lines required
			// note: rest of the file is ignored
			crc = new CommandReplayConfiguration();
			crc.setApplicationURL(br.readLine().split("=")[1]);
			crc.setSessionCookieName(br.readLine().split("=")[1]);
			crc.setRequestParameterName(br.readLine().split("=")[1]);
			crc.setRequestParameterValue(br.readLine().split("=")[1]);
			
			// close the stream
			br.close();
		}
		
		catch (FileNotFoundException e) {
			System.out.println("[E] Configuration file was not found.");
		}
		
		catch (IOException e) {
			System.out.println("[E] Configuration file could not be read.");
		}
	}
}
