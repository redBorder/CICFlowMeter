package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;

import java.io.File;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import cic.cs.unb.ca.jnetpcap.worker.TrafficFlowWorker;

public class Listen {

    public static final Logger logger = LoggerFactory.getLogger(Listen.class);
    
    public static void main(String[] args) {

        String outPath;
        String interfaceName;
        Integer fileTimeout;
        Integer maxCsvFiles;
        
        if (args.length < 1) {
            logger.info("Please define output directory");
            return;
        }
        outPath = args[0];
        File in = new File(outPath);

        if(in==null || !in.exists()){
            logger.info("The pcap file or folder does not exist! -> {}",outPath);
            return;
        }
        logger.info("Out folder: {}",outPath);
        
        if (args.length < 2) {
            logger.info("Please define interface");
            return;
        }
        interfaceName = args[1];
        logger.info("interface: {}",interfaceName);

        if (args.length < 3) {
            logger.info("Please define file timeout, use -1 for unlimited");
            return;
        }
        fileTimeout = Integer.parseInt(args[2]);
        logger.info("timeout: {}", fileTimeout);

        if (args.length < 3) {
            logger.info("Please define maximum numbver of csv files to store");
            return;
        }
        maxCsvFiles = Integer.parseInt(args[3]);
        logger.info("timeout: {}", fileTimeout);

        listenIf(outPath, interfaceName, fileTimeout, maxCsvFiles);

    }

    private static void listenIf(String outPath, String interfaceName, Integer fileTimeout, Integer maxCsvFiles) {
        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;

    	if(outPath==null) {
            return;
        }

    	if(interfaceName==null) {
            return;
        }

    	if(fileTimeout==null) {
            fileTimeout=-1;
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(outPath, interfaceName, fileTimeout, maxCsvFiles));

    }
    
    static class FlowListener implements FlowGenListener {
        private TrafficFlowWorker mWorker;
        
        private String outPath;
        private String ifName;
        private Integer fileTimeout;
        private Integer loop;
        private Integer count;
        private Long currentTime;

        public FlowListener(String outPath, String interfaceName, Integer fileTimeout, Integer loop) {
            this.outPath = outPath;
            this.ifName = interfaceName;
            this.fileTimeout = fileTimeout;
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
	    	        //write flows to csv file
	    	        //String filename = LocalDate.now().format(DateTimeFormatter.ofPattern("YYMMdd")).toString()+ LocalTime.now().format(DateTimeFormatter.ofPattern("HHmm")).toString() + FlowMgr.FLOW_SUFFIX;
	    	        if ((System.currentTimeMillis()-currentTime) > fileTimeout*1000) {
	    	        	count = (count+1)%loop;
	    	        	currentTime=System.currentTimeMillis();
	    	        }
	    	        String filename = "data_"+Integer.toString(count) + FlowMgr.FLOW_SUFFIX;

	            	insertFlow((BasicFlow) event.getNewValue(), filename);
	            }
	        });
	        mWorker.execute();
	        logger.info("waiting...");
	        while (true) {
	        	 // waiting for incoming flow data
	        }
	    }
	
	    private void insertFlow(BasicFlow flow, String fileName) {
	        List<String> flowStringList = new ArrayList<>();
	        List<String[]> flowDataList = new ArrayList<>();
	        String flowDump = flow.dumpFlowBasedFeaturesEx();
	        flowStringList.add(flowDump);
	        flowDataList.add(StringUtils.split(flowDump, ","));
	
	        
	        logger.info("insert flow : " + fileName);
            InsertCsvRow.insert(FlowFeature.getHeader(),flowStringList,outPath,fileName, fileTimeout);
		    }
    }

}
