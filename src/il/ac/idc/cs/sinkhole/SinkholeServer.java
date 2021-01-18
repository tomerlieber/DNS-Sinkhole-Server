package il.ac.idc.cs.sinkhole;

import java.io.IOException;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class SinkholeServer {

    // Constants
    private static final int maxIterations = 16;
    private static final int dnsPort = 53;
    private static final int bufSize = 1024;
    private static final int serverPort = 5300;

    // Data members
    private static List<String> rootServers;
    private static DatagramSocket serverSocket;
    private static Random rnd;
    private static Set<String> blockList;

    static {
        rootServers = Stream.of("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m")
                .map(x -> x.concat(".root-servers.net")).collect(Collectors.toList());
        rnd = new Random();
        blockList = new HashSet<>();
    }

    public static void main(String[] args) {

        try {

            if (args.length > 1) {
                System.err.println("Usage: il.ac.idc.cs.sinkhole.SinkholeServer [blocklist-path]");
                return;
            }

            if (args.length == 1) {
                List<String> lines = Files.readAllLines(Path.of(args[0]));
                blockList.addAll(lines);
                System.out.println("Loaded block list into the memory");
            }

            serverSocket = new DatagramSocket(serverPort);
            System.out.println("The DNS server is listening on port 5300");

            while (true) {

                byte[] baseData = new byte[bufSize];
                DatagramPacket basePacket = new DatagramPacket(baseData, baseData.length);

                System.out.println();
                System.out.println("Waiting for the next DNS query...");
                // Blocks until datagram received from the client
                serverSocket.receive(basePacket);

                DnsParser baseParser = new DnsParser(baseData);

                while (baseParser.isResponse()) {
                    serverSocket.receive(basePacket);
                    baseParser.setData(baseData);
                }

                int basePacketID = baseParser.getID();
                InetAddress clientAddress = basePacket.getAddress();
                int clientPort = basePacket.getPort();

                String domainName = baseParser.getQuestionName();

                System.out.println("Received a query from the client: \t\t\t" + clientAddress);
                System.out.println("The query seeks to resolve the domain name: " + domainName);

                ExecutorService service = Executors.newSingleThreadExecutor();

                try {
                    Runnable r = () -> {
                        try {
                            resolveDnsQuery(domainName, baseParser, basePacket, clientAddress, clientPort, basePacketID);
                        }
                        catch (IOException ex) {
                            System.err.println("Can't resolve the query because of the follow error: " + ex.getMessage());
                        }
                    };

                    Future<?> f = service.submit(r);

                    f.get(5, TimeUnit.SECONDS); // attempt the task for five seconds
                }
                catch (TimeoutException ex) {

                    baseParser.changeHeaderFlags((byte) 2); // response code 2 indicates server failure.
                    DatagramPacket sendPacket = new DatagramPacket(baseParser.getData(), basePacket.getLength(), clientAddress, clientPort);
                    serverSocket.send(sendPacket);

                    System.out.println("Can't resolve the query because it takes more than 5 seconds to handle it");
                    if (!serverSocket.isClosed()) {
                        serverSocket.close();
                    }
                    serverSocket = new DatagramSocket(5300);
                }
                finally {
                    service.shutdown();
                }
            }
        }
        catch (SocketException ex) {
            System.err.println("The DNS server can't create a new socket at port " + serverPort);
        }
        catch (Exception ex) {
            System.err.println("The DNS server stopped work because of the following error: " + ex.getMessage());
        } finally {
            if (serverSocket != null) {
                serverSocket.close();
            }
        }
    }

    private static void resolveDnsQuery(String domainName, DnsParser baseParser, DatagramPacket basePacket, InetAddress clientAddress, int clientPort, int basePacketID) throws IOException{

        // Check if the domain name that needs to be resolved is in the specified block list
        if (blockList.contains(domainName)) {

            baseParser.changeHeaderFlags((byte) 3); // response code 3 indicates NXDOMAIN error.
            sendPacket(basePacket, clientAddress, clientPort);
            System.out.println("Can't resolve the query because the domain name is in the block list");
            return;
        }

        DnsParser parser = null;
        byte[] receiveData;
        DatagramPacket receivePacket = null;

        int responseCode = 0;
        int answerCount = 0;
        int nameServerCount = 1;

        int iteration = 1;

        while (responseCode == 0 && answerCount == 0 && nameServerCount > 0 && iteration <= maxIterations) {

            // First iteration: Send the DNS query to a randomly chosen root server
            // Next iterations: Send the query to the first name server in the AUTHORITY section
            String nameServer = (iteration == 1) ? getRandomRootServer() : parser.getResourceName();
            InetAddress IPAddress = InetAddress.getByName(nameServer);

            sendPacket(basePacket, IPAddress, dnsPort);

            System.out.println(iteration + ". Sent a DNS query to: \t\t\t\t\t" + IPAddress.toString());

            receiveData = new byte[bufSize];
            receivePacket = new DatagramPacket(receiveData, receiveData.length);

            serverSocket.receive(receivePacket);

            parser = new DnsParser(receiveData);

            while (!parser.isResponse() || parser.getID() != basePacketID) {
                serverSocket.receive(receivePacket);
                parser = new DnsParser(receiveData);
            }

            iteration++;

            responseCode = parser.getResponseCode();
            answerCount = parser.getAnswerCount();
            nameServerCount = parser.getNameServerCount();
        }

        if (iteration > maxIterations) {

            baseParser.changeHeaderFlags((byte) 2); // response code 2 indicates server failure.
            sendPacket(basePacket, clientAddress, clientPort);
            System.out.println("Can't resolve the query because the number of iterations exceeds 16");
            return;
        }

        // send the final response to the client

        // TODO: What if one of the name node give me an error. why I change the response code to 0?
        // parser.changeHeaderFlags((byte)responseCode); // TODO: I think I need to remove the follow line with this one.

        parser.changeHeaderFlags((byte) 0); // response code 0 indicates no error.
        sendPacket(receivePacket, clientAddress, clientPort);
        System.out.println("Resolved the query!");
    }

    private static String getRandomRootServer() {
        int randomIndex = rnd.nextInt(rootServers.size());
        return rootServers.get(randomIndex);
    }

    private static void sendPacket(DatagramPacket packet, InetAddress dstAddress, int dstPort) throws IOException {
        packet.setAddress(dstAddress);
        packet.setPort(dstPort);
        serverSocket.send(packet);
    }
}
