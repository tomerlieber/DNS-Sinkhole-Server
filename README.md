# DNS Sinkhole Server
A DNS Sinkhole server that iteratively resolves any request for domains that not included in a given list of domains

## How to use?
1. Download the project.
2. Build the project using the follow command:

    ```$ javac -d out/ -Xlint src/il/ac/idc/cs/sinkhole/*.java```

3. Run the server using the following command:

    ```$ java -cp out il.ac.idc.cs.sinkhole.SinkholeServer```

    or if you want that the server will use a block list file called blocklist.txt:

    ```$ java -cp out il.ac.idc.cs.sinkhole.SinkholeServer blocklist.txt```

## A typical flow of the server:
The server is listening on port 5300 ⇨

The server receives a DNS request ⇨

The server sends the request to a random root server ⇨

The server received a response from the random root server ⇨

Until there is no answer, the server sends a request to the next DNS server. The name of the next DNS server is extracted from the authority section of the last response ⇨

Send the final response to the client

## Additional info:
* Supports reading compressed data according to RFC1035 section 4.1.4.
* Supports a valid DNS query of type A only.
* Implements a query timeout of 5 seconds, so for example if a root server doesn’t respond, the server will cancel the request and advance to the next one.
* The block list file is a text file containing one valid domain name to block per line. You can view an example file in the root directory of the project.
* The project was tested with Java 11.
