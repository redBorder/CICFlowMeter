package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import cic.cs.unb.ca.jnetpcap.worker.TrafficFlowWorker;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import org.apache.commons.cli.*;

public class Listen {

    public static final Logger logger = LoggerFactory.getLogger(Listen.class);
    
    public static void main(String[] args) {

        String outPath;
        String interfaceName;
        Integer fileTimeout;
        Integer maxCsvFiles;
        String destinationUrl;
        
        Options options = new Options();
        Option help = new Option("h", "help", true, "show this help");
        help.setRequired(false);
        options.addOption(help);
        Option output = new Option("o", "output", true, "output directory to write csv files");
        output.setRequired(false);
        options.addOption(output);
        Option iface = new Option("i", "interface", true, "interface to listen to (required)");
        output.setRequired(true);
        options.addOption(iface);
        Option ftimeout = new Option("t", "filetimeout", true, "time (seconds) before starting to write in new csv file. Use -1 for unlimited (default)");
        output.setRequired(false);
        options.addOption(ftimeout);
        Option maxcsvf = new Option("m", "maxcsvfiles", true, "number of csv files we keep before rotating");
        output.setRequired(false);
        options.addOption(maxcsvf);
        Option destinationurl = new Option("d", "destinationUrl", true, "destination url to send the flows to");
        output.setRequired(false);
        options.addOption(destinationurl);
        
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        outPath=null;
        destinationUrl=null;
        interfaceName=null;
        
        // by default we write in one csv file, unlimited time
        fileTimeout=-1;
        
        // by default we will keep track of 10 csv files
        maxCsvFiles=10;
        		
        try {
            cmd = parser.parse(options, args);
            
            if (cmd.hasOption("h")) {
                formatter.printHelp("listen", options);
                System.exit(0);
            }
            
            interfaceName = cmd.getOptionValue("interface");
            if (interfaceName == null) {
                formatter.printHelp("listen", options);
                System.exit(0);            	
            }

            if (cmd.hasOption("o")) {
                outPath = cmd.getOptionValue("output");
            	
                if (cmd.hasOption("t")) {
                	fileTimeout=Integer.parseInt(cmd.getOptionValue("filetimeout"));
                	if (!(fileTimeout > 0)) {
                    	logger.info("Filetimeout should be bigger than 0");
                		System.exit(1);
                	}
                }            	
                if (cmd.hasOption("m")) {
                	maxCsvFiles=Integer.parseInt(cmd.getOptionValue("maxcsvfiles"));
                	if (!(maxCsvFiles > 0)) {
                    	logger.info("Max Csv files should be bigger than 0");
                		System.exit(1);
                	}
                }            	
            }
                        
            if (cmd.hasOption("t")) {
                outPath = cmd.getOptionValue("output");
            }
            
            if (cmd.hasOption("d")) {
                destinationUrl = cmd.getOptionValue("destinationUrl");
            }
            listenIf(outPath, interfaceName, fileTimeout, maxCsvFiles, destinationUrl);


        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("listen", options);
            System.exit(1);
        }

    }

    private static void listenIf(String outPath, String interfaceName, Integer fileTimeout, Integer maxCsvFiles, String destinationUrl) {
        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;

    	if(interfaceName==null) {
            return;
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(outPath, interfaceName, fileTimeout, maxCsvFiles, destinationUrl));

    }
    
    static class FlowListener implements FlowGenListener {
        private TrafficFlowWorker mWorker;
        
        private String outPath;
        private String ifName;
        private Integer fileTimeout;
        private Integer loop;
        private String destinationUrl;
        private Integer count;
        private Long currentTime;

        public FlowListener(String outPath, String interfaceName, Integer fileTimeout, Integer loop, String destinationUrl) {
            this.outPath = outPath;
            this.ifName = interfaceName;
            this.fileTimeout = fileTimeout;
            this.destinationUrl = destinationUrl;
            this.loop = loop;
            this.count = 0;
            this.currentTime=System.currentTimeMillis();
            
            // start the worker to listen to the interface
            start();
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {
            // we will keep listening forever, we do not come here
        }
    
    
	    private void start() {
		
	        if (mWorker != null && !mWorker.isCancelled()) {
	            return;
	        }
	
	        mWorker = new TrafficFlowWorker(ifName);
	        mWorker.addPropertyChangeListener(event -> {
	            if (TrafficFlowWorker.PROPERTY_FLOW.equalsIgnoreCase(event.getPropertyName())) {

	    	        if ((System.currentTimeMillis()-currentTime) > fileTimeout*1000) {
	    	        	count = (count+1)%loop;
	    	        	currentTime=System.currentTimeMillis();
	    	        }
	    	        String filename = "data_"+Integer.toString(count) + FlowMgr.FLOW_SUFFIX;

	            	try {
						insertFlow((BasicFlow) event.getNewValue(), filename);
					} catch (IOException e) {
						e.printStackTrace();
					}
	            }
	        });
	        mWorker.execute();
	        logger.info("waiting...");
	        while (true) {
	        	 // waiting for incoming flow data
	        }
	    }
	
	    private void insertFlow(BasicFlow flow, String fileName) throws IOException {
	        List<String> flowStringList = new ArrayList<>();
	        String flowDump = flow.dumpFlowBasedFeaturesEx();
	        flowStringList.add(flowDump);
	
	        logger.info("insert flow : " + fileName);
            if (outPath != null) InsertCsvRow.insert(FlowFeature.getHeader(),flowStringList,outPath,fileName, fileTimeout);
	        if (destinationUrl != null) sendFlow("["+flow.dumpFlowBasedFeaturesJson()+"]");
		}
	    
	    private void sendFlow(String json) throws IOException {

	        logger.info("post flow : " + json);
	    	CloseableHttpClient httpClient = HttpClientBuilder.create().build();

	    	try {
	    		long epochtime = System.currentTimeMillis()/1000;
	    		String url = destinationUrl+"/"+Long.toString(epochtime);
	    		logger.info("url : "+url);
	    	    HttpPost request = new HttpPost(url);
	    	    
	    	    StringEntity params = new StringEntity(json, ContentType.APPLICATION_FORM_URLENCODED);
	    	    request.addHeader("content-type", "application/json");
	    	    request.setEntity(params);
	    	    httpClient.execute(request);    	    
	    	    
	    	// handle response here...
	    	} catch (Exception ex) {
	    	    logger.info("exeption : "+ex.toString());
	    	} finally {
	    	    httpClient.close();
	    	}
	    }
    }

}
