package il.ac.idc.cs.sinkhole;

import java.io.IOException;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class SinkholeServer {

    // Constants
    private static final int maxIterations = 16;
    private static final int dnsPort = 53;
    private static final int bufSize = 1024;


    // Data members
    private static List<String> rootServers;
    private static DatagramSocket serverSocket;
    private static Random rnd;

    static {
        rootServers = Stream.of("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m")
                .map(x -> x.concat(".root-servers.net")).collect(Collectors.toList());
        rnd = new Random();
    }

    public static void main(String[] args) {

        try {

            if (args.length > 1) {
                System.err.println("Usage: il.ac.idc.cs.sinkhole.SinkholeServer [blocklist-path]");
                return;
            }

            Set<String> blockList = null;
            if (args.length == 1) {
                List<String> lines = Files.readAllLines(Path.of(args[0]));
                blockList = new HashSet<>(lines);
                System.out.println("Loaded block list into the memory.");
            }

            serverSocket = new DatagramSocket(5300);
            System.out.println("The DNS server is listening on port 5300");

            while (true) {

                byte[] baseData = new byte[bufSize];
                DatagramPacket basePacket = new DatagramPacket(baseData, baseData.length);

                // Blocks until datagram received from the client
                serverSocket.receive(basePacket);

                DnsParser baseParser = new DnsParser(baseData);

                int baseID = baseParser.getID();
                InetAddress clientAddress = basePacket.getAddress();
                int clientPort = basePacket.getPort();

                String domainName = baseParser.getQuestionName();

                System.out.println();
                System.out.println("Received a DNS query from: \t" + domainName);

                // Check if the domain name that needs to be resolved is in the specified block list
                if (blockList != null && blockList.contains(domainName)) {

                    baseParser.changeHeaderFlags((byte) 3); // response code 3 indicates NXDOMAIN error.

                    DatagramPacket sendPacket = new DatagramPacket(baseParser.getData(), basePacket.getLength(), clientAddress, clientPort);
                    serverSocket.send(sendPacket);
                    System.out.println("Can't resolve the query because the domain name is in the block list");
                    continue;
                }

                DnsParser parser = null;
                byte[] recieveData = null;
                DatagramPacket recievePacket = null;

                int responseCode = 0;
                int answerCount = 0;
                int nameServerCount = 1;

                int iteration = 1;

                while (responseCode == 0 && answerCount == 0 && nameServerCount > 0 && iteration <= maxIterations) {

                    // First iteration: Send the DNS query to a randomly chosen root server
                    // Next iterations: Send the query to the first name server in the AUTHORITY section
                    String nameServer = (iteration == 1) ? getRandomRootServer() : parser.getResourceName();
                    InetAddress IPAddress = InetAddress.getByName(nameServer);

                    if (nameServer.contains("local")) { // TODO: continue here
                        String test = parser.getResourceName();
                    }

                    basePacket.setAddress(IPAddress);
                    basePacket.setPort(dnsPort);

                    serverSocket.send(basePacket);
                    System.out.println("\tSent a DNS query to: \t" + IPAddress.getHostName());

                    recieveData = new byte[bufSize];
                    recievePacket = new DatagramPacket(recieveData, recieveData.length);

                    serverSocket.receive(recievePacket);

                    parser = new DnsParser(recieveData);

                    while (!parser.isResponse() || parser.getID() != baseID) {
                        serverSocket.receive(recievePacket);
                        parser = new DnsParser(recieveData);
                    }

                    iteration++;

                    responseCode = parser.getResponseCode();
                    answerCount = parser.getAnswerCount();
                    nameServerCount = parser.getNameServerCount();
                }

                if (iteration > maxIterations) {

                    baseParser.changeHeaderFlags((byte) 2); // response code 2 indicates server failure.
                    DatagramPacket sendPacket = new DatagramPacket(baseData, basePacket.getLength(), clientAddress, clientPort);
                    serverSocket.send(sendPacket);

                    System.out.println("Can't resolve the query because the number of iterations exceeds 16");
                    continue;
                }

                // send the final response to the client
                parser.changeHeaderFlags((byte) 0); // response code 0 indicates no error. // TODO: What if one of the name node give me an error. why I change the response code to 0?

                DatagramPacket sendPacket = new DatagramPacket(recieveData, recievePacket.getLength(), clientAddress, clientPort);
                serverSocket.send(sendPacket);
                System.out.println("Resolved the query!");
            }
        } catch (Exception ex) {
            System.err.println(ex.getMessage());
        } finally {
            if (serverSocket != null) {
                serverSocket.close();
            }
        }
    }

    private static String getRandomRootServer() {
        int randomIndex = rnd.nextInt(rootServers.size());
        return rootServers.get(randomIndex);
    }

    private static void sendMessage(byte[] data, int length, InetAddress destAddress, int dstPort) throws IOException {
        DatagramPacket sendPacket = new DatagramPacket(data, length, destAddress, dstPort);
        serverSocket.send(sendPacket);
    }
}
