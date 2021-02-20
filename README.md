# DNS Sinkhole Server
A DNS Sinkhole server that iteratively resolves any request for domains that not included in a given list of domains

## What is a typical flow of the server?
The server is listening on port 5300  🠊

The server receives a DNS request from a client  🠊

The server checks if the domain name that needs to be resolved is specified in the blocklist file. If yes, return an error response  🠊

The server sends the request to a random root server  🠊

The server received a response from the random root server  🠊

Until there is no answer, the server sends a request to the next DNS server. The name of the next DNS server is extracted from the authority section of the last response  🠊

Send the final response to the client

## How to use?
1. Download the project.
2. Build the project using the follow command:

    ```$ javac -d out/ -Xlint src/il/ac/idc/cs/sinkhole/*.java```

3. Run the server using the following command:

    ```$ java -cp out il.ac.idc.cs.sinkhole.SinkholeServer```

    or if you want that the server will use a block list file called blocklist.txt:

    ```$ java -cp out il.ac.idc.cs.sinkhole.SinkholeServer blocklist.txt```

## Additional info:
* Supports reading compressed data according to <a href="https://tools.ietf.org/html/rfc1035">RFC 1035<a> section 4.1.4
* Supports a valid DNS query of type A only
* Implements a query timeout of 5 seconds, so for example if a root server doesn’t respond, the server will cancel the query and advance to the next one
* The block list file is a text file containing one valid domain name to block per line. You can view an example file in the root directory of the project
* The project was tested with Java 11
