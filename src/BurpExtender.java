import java.util.*;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.io.*;

public class BurpExtender {
	int parameter_count = 0;
	int request_count = 0;

	public burp.IBurpExtenderCallbacks mCallbacks;

	public void registerExtenderCallbacks(burp.IBurpExtenderCallbacks callbacks) {
		mCallbacks = callbacks;
	}

    public byte[] processProxyMessage(
            int messageReference,
            boolean messageIsRequest,
            String remoteHost,
            int remotePort,
            boolean serviceIsHttps,
            String httpMethod,
            String url,
            String resourceType,
            String statusCode,
            String responseContentType,
            byte[] message,
            int[] interceptAction)
    {
    	String myStr = new String(message);

    	if (messageIsRequest) {
    		try {
    			if (httpMethod.equals("GET")) {
    				Pattern p = Pattern.compile("\\?(((.*)=(.*)&*)+)\\sHTTP");
    				Matcher m = p.matcher(myStr); // get a matcher object
    				boolean matchFound = m.find();
    				String param_string = "";
    				String groupstr = "";

    				if (matchFound) {
    					groupstr = m.group(1);
    					request_count = request_count + 1;

    					// Writing details to Log File
    					String border = "---------------------------------------------------\r\n";
    					String req_count = "Dynamic Request: " + request_count + "\r\n";
    					SaveToFile(remoteHost, border, false);
    					SaveToFile(remoteHost, req_count, false);
    					SaveToFile(remoteHost, httpMethod, false);
    					SaveToFile(remoteHost, url, false);
    					SaveToFile(remoteHost, groupstr, false);

    					String[] params = groupstr.split("&");
    					parameter_count = parameter_count + params.length;

    					for (int i = 0; i < params.length; i++) {
    						String parameter = params[i];
    						if (parameter.matches(".*=$")) {
    							String rand_string = random_string();
    							String replace = parameter.replaceAll(parameter, parameter + rand_string);
    							param_string = param_string + replace;
    							if (i != params.length - 1) {
    								param_string += "&";
    							}
    						} else {
    							param_string = param_string + parameter;
    							if (i != params.length - 1) {
    								param_string += "&";
    							}
    						}
    					}

    					SaveToFile(remoteHost, param_string, false);
    					myStr = myStr.replace(groupstr, param_string);
    				}
    			} else if (httpMethod.equals("POST")) {

    				Pattern p11 = Pattern.compile("multipart/form-data");
    				Matcher m11 = p11.matcher(myStr); // get a matcher object
    				boolean matchFound11 = m11.find();

    				if (!matchFound11) {
    					Pattern p1 = Pattern
    					.compile("\\r\\n\\r\\n(((.*)=(.*)&*)+)");
    					Matcher m1 = p1.matcher(myStr); // get a matcher object
    					boolean matchFound1 = m1.find();
    					String param_string = "";
    					String groupstring = "";
    					if (matchFound1) {
    						groupstring = m1.group(1);
    						request_count = request_count + 1;

    						// Writing details to Log File
    						String border = "---------------------------------------------------\r\n";
    						String req_count = "Dynamic Request: " + request_count + "\r\n";
    						SaveToFile(remoteHost, border, false);
    						SaveToFile(remoteHost, req_count, false);
    						SaveToFile(remoteHost, httpMethod, false);
    						SaveToFile(remoteHost, url, false);
    						SaveToFile(remoteHost, groupstring, false);

    						String[] params = groupstring.split("&");
    						parameter_count = parameter_count + params.length;

    						for (int i = 0; i < params.length; i++) {
    							String parameter = params[i];
    							if (parameter.matches(".*=$")) {
    								String rand_string = random_string();
    								String replace = parameter.replaceAll(parameter, parameter + rand_string);
    								param_string = param_string + replace;
    								if (i != params.length - 1) {
    									param_string += "&";
    								}
    							} else {
    								param_string = param_string + parameter;
    								if (i != params.length - 1) {
    									param_string += "&";
    								}
    							}
    						}

    						SaveToFile(remoteHost, param_string, false);
    						myStr = myStr.replace(groupstring, param_string);
    					}
    				} else {
    					request_count = request_count + 1;

    					// Writing details to Log File
    					String border = "---------------------------------------------------\r\n";
    					String req_count = "Dynamic Request: " + request_count
    					+ "\r\n";
    					SaveToFile(remoteHost, border, false);
    					SaveToFile(remoteHost, req_count, false);
    					SaveToFile(remoteHost, httpMethod, false);
    					SaveToFile(remoteHost, url, false);
    					SaveToFile(remoteHost, "multipart/form-data Request", false);

    					Pattern pbound = Pattern.compile("boundary=(.*)");
    					Matcher mbound = pbound.matcher(myStr);
    					boolean matchfnd = mbound.find();

    					if (matchfnd) {
    						String boundary = mbound.group(1);
    						String[] parameters = myStr.split(boundary);
    						parameter_count = parameter_count
    						+ (parameters.length - 3);

    						for (int i = 2; i < parameters.length; i++) {
    							String test = parameters[i];
    							Pattern pbound1 = Pattern.compile("name=\"(.*)\"\\r\\n\\r\\n(.*)\\r\\n--");
    							Matcher mbound1 = pbound1.matcher(test);
    							boolean matchfnd1 = mbound1.find();
    							if (matchfnd1) {
    								String param_list = mbound1.group(0);
    								String param_name = mbound1.group(1);
    								String param_value = mbound1.group(2);

    								if (param_value.matches("")) {
    									String rand_str = random_string();
    									String rep_str = "name=\"" + param_name	+ "\"\r\n\r\n" + rand_str + "\r\n--";
    									myStr = myStr.replace(param_list, rep_str);
    								}
    							}
    						}
    					}
    				}
    			}

    			String total_count = "\nTotal Parameters till now : "
    				+ parameter_count + "\r\n";
    			SaveToFile(remoteHost, total_count, false);

    		}

    		catch (Exception e) {
    			e.printStackTrace();
    		}
    	}

    	return myStr.getBytes();
    }

    private String random_string() {
    	// Random String
    	String s3;
    	s3 = UUID.randomUUID().toString();
    	s3 = s3.substring(0, 7);
    	return s3;
    }

    private void SaveToFile(String fileName, String st2write, boolean printTime) {
    	File aFile = new File(fileName + ".txt");
    	Date now = new Date();
    	try {
    		BufferedWriter out = new BufferedWriter(new FileWriter(aFile, aFile
    				.exists()));
    		if (printTime) {
    			out.write("\r\n\r\n" + now.toString() + "\r\n");
    		}
    		out.write(st2write + "\r\n");
    		out.close();
    	} catch (IOException e) {
    		e.printStackTrace();
    	}
    }

}