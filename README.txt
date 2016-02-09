ElasticPot - Python edition









Docker stuff:

1. Build the image: docker build -t elasticpotpy .

2. docker run -p 9200:9200 -t -i elasticpotpy /opt/start.sh

As ElasticpotPY supports the DTAG T-Pot directory layout, ElasticpotPY will reuse the
config to e.g. send data back to the core system.

To setup the valumes correctly, use this command:

docker run -p 9200:9200 -v /data:/data -t -i schmalle/elasticpotPY /opt/start.sh

If you want to test it locally e.g. on a MAC, create a data directory under your home directory.
(otherwise the mapping is not working)

docker run -p 9200:9200 -v $HOME/data:/data -t -i schmalle/elasticpotPY /opt/start.sh



        Date curDate = new Date()
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-ddhh:mm:ss");

        String DateToStr = format.format(curDate)

        DateToStr = DateToStr.substring(0, 10) + "T" + DateToStr.substring(10)

        def dumpStr = "{\"timestamp\":\"" + DateToStr + "\",\"event_type\":\"alert\",\"src_ip\":\""+attackerIP+"\",\"src_port\":44927,\"dest_ip\":\"127.0.0.1\",\"dest_port\":9200,\"honeypot\":{\"name\":\"Elasticpot\",\"nodeid\":\"elasticsearch\"}}\r\n"
