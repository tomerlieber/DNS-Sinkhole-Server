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
    static final int maxIterations = 16;
    static final int dnsPort = 53;
    static final int bufSize = 1024;


    // Data members
    static List<String> rootServers;
    static DatagramSocket serverSocket;
    static Random rnd;

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

                byte firstByte = baseData[0];

                InetAddress clientAddress = basePacket.getAddress();
                int clientPort = basePacket.getPort();

                DnsParser baseParser = new DnsParser(baseData);

                String domainName = baseParser.getQuestionName();

                System.out.println("Received a DNS query for domain name: " + domainName);

                // Check if the domain name that needs to be resolved is in the specified block list
                if (blockList != null && blockList.contains(domainName)) {

                    baseParser.changeHeaderFlags((byte)3); // response code 3 indicates NXDOMAIN error.

                    DatagramPacket sendPacket = new DatagramPacket(baseParser.getData(), basePacket.getLength(), clientAddress, clientPort);
                    serverSocket.send(sendPacket);
                    continue;
                }

                // Send the DNS query to a randomly chosen root server
                InetAddress IPAddress = getRandomRootServerIP();

                baseData[0]++;
                basePacket.setData(baseData, 0, basePacket.getLength());
                basePacket.setAddress(IPAddress);
                basePacket.setPort(dnsPort);

                serverSocket.send(basePacket);

                byte[] recieveData = new byte[bufSize];
                DatagramPacket recievePacket = new DatagramPacket(recieveData, recieveData.length);

                serverSocket.receive(recievePacket);

                while (recieveData[0] != baseData[0]) {
                    serverSocket.receive(recievePacket);
                }

                DnsParser parser = new DnsParser(recieveData);

                // TODO: Continue here tomorrow.

                

                int responseCode = parser.getResponseCode();
                int answerCount = parser.getAnswerCount();
                int nameServerCount = parser.getNameServerCount();

                int iteration = 0;

                while (responseCode == 0 && answerCount == 0 && nameServerCount > 0 && iteration < maxIterations) {

                    // Send the query to the first name server in the AUTHORITY section
                    String nameServer = parser.getResourceName();

                    IPAddress = InetAddress.getByName(nameServer);

                    baseData[0]++;
                    basePacket.setData(baseData, 0, basePacket.getLength());
                    basePacket.setAddress(IPAddress);
                    basePacket.setPort(dnsPort);

                    serverSocket.send(basePacket);

                    recieveData = new byte[bufSize];
                    recievePacket = new DatagramPacket(recieveData, recieveData.length);

                    serverSocket.receive(recievePacket);

                    while (recieveData[0] != baseData[0]) {
                        serverSocket.receive(recievePacket);
                    }

                    iteration++;

                    parser = new DnsParser(recieveData);

                    responseCode = parser.getResponseCode();
                    answerCount = parser.getAnswerCount();
                    nameServerCount = parser.getNameServerCount();
                }

                if (iteration >= maxIterations) {
                    System.out.println("Can't resolve the query because the number of iterations exceeds 16");

                    baseParser.changeHeaderFlags((byte) 2); // response code 2 indicates server failure.

                    baseData[0] = firstByte;
                    DatagramPacket sendPacket = new DatagramPacket(baseData, basePacket.getLength(), clientAddress, clientPort);
                    serverSocket.send(sendPacket);
                    continue;
                }

                // send the final response to the client
                // changeHeaderFlags(recieveData, (byte) 0);
                parser.changeHeaderFlags((byte)0); // response code 0 indicates no error. // TODO: What if one of the name node give me an error. why I change the response code to 0?

                recieveData[0] = firstByte;
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

    private static class DnsParser {

        final int QRoffset = 2;
        final int RcodeOffset = 3;
        final int ANCountOffset = 6;
        final int NSCountOffset = 8;
        final int SectionQuestionOffset = 12;

        private byte[] data;

        private DnsParser(byte[] data) {
            this.data = data;
        }

        private byte[] getData() {
            return this.data;
        }

        // response code (RCODE) is 0 if there is no error
        private int getResponseCode() {
            return createNum(data[RcodeOffset], 4, 4);
        }

        // ANCOUNT = an unsigned 16 bit integer specifying the number of resource records in the answer section.
        private int getAnswerCount() {
            return createNum(data[ANCountOffset], data[ANCountOffset + 1]);
        }

        // NSCOUNT = an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
        private int getNameServerCount() {
            return createNum(data[NSCountOffset], data[NSCountOffset + 1]);
        }

        private String getQuestionName() {

            // Assume the number of entries in the question section is 1.
            StringBuilder domainName = new StringBuilder();

            int i = SectionQuestionOffset; // The question section offset
            int length = data[i];

            while (length > 0) {

                i++;

                for (int j = i; j < i + length; j++) {
                    domainName.append((char) data[j]);
                }

                i += length;
                length = data[i];

                if (length > 0) {
                    domainName.append(".");
                }
            }

            return domainName.toString();
        }

        private String getResourceName() {
            int index = skipQueriesSection(data, SectionQuestionOffset);

            index = skipToResourceLength(data, index);

            int resourceLength = createNum(data[index], data[index + 1]);

            index += 2;

            // Assume the number of entries in the question section is 1.
            StringBuilder domainName = new StringBuilder();

            int i = index; // The question section offset

            while (i < index + resourceLength) {

                // Check if the last two MSB are ones.
                if ((data[i] & 0b11000000) == 0b11000000) {

                    int currIndex = ((data[i] & 0b00111111) << 8) | data[i + 1];

                    int currLength = data[currIndex];
                    while (currLength > 0) {

                        for (int j = currIndex + 1; j < currIndex + 1 + currLength; j++) {
                            domainName.append((char) data[j]);
                        }

                        currIndex += currLength + 1;
                        currLength = data[currIndex];

                        if (currLength > 0) {
                            domainName.append(".");
                        }
                    }

                    i += 2;
                } else {

                    int currLength = data[i];

                    for (int j = i + 1; j < i + 1 + currLength; j++) {
                        domainName.append((char) data[j]);
                    }

                    i += currLength + 1;
                }

                if (i < index + resourceLength - 1) {
                    domainName.append(".");
                }
            }

            return domainName.toString();
        }

        private void changeHeaderFlags(byte responseCode) {

            // Change QR to one to indicate the message is a response
            byte qr = (byte) (data[QRoffset] | 0b10000000);
            data[QRoffset] = qr;

            // Change rd to one to indicate recursion desired
            byte rd = (byte) (data[QRoffset] | 0b00000001); // TODO: make sure I need to add it.
            data[QRoffset] = rd;

            // Change ra to one to indicate recursion available
            byte ra = (byte) (data[RcodeOffset] | 0b10000000); // TODO: make sure I need to add it.
            data[RcodeOffset] = ra;

            // Change AA to zero to specify that the responding name server
            // is not an authority for the domain name in question section.
            byte aa = (byte) (data[QRoffset] & 0b11111011);
            data[QRoffset] = aa;

            // change response code to Server failure
            byte rcode = (byte) (data[RcodeOffset] | responseCode);
            data[RcodeOffset] = rcode;
        }

        private boolean isResponse() {
            return (data[QRoffset] & 0b10000000) != 0;
        }
    }

    private static void sendMessage(byte[] data, int length, InetAddress destAddress, int dstPort) throws IOException {
        DatagramPacket sendPacket = new DatagramPacket(data, length, destAddress, dstPort);
        serverSocket.send(sendPacket);
    }

    private static InetAddress getRandomRootServerIP() throws UnknownHostException {
        int randomIndex = rnd.nextInt(rootServers.size());
        String rootServer = rootServers.get(randomIndex);
        return InetAddress.getByName(rootServer);
    }

    private static int skipToResourceLength(byte[] recieveData, int index) {

        // Skip the domain name to which this resource record pertains.
        while (recieveData[index] != 0) {
            index++;
        }

        // Skip Type, Class and TTL (notice that TTL is 4 bytes)
        index += 8;

        return index;
    }

    private static int skipQueriesSection(byte[] recieveData, int SectionQuestionOffset) {

        int index = SectionQuestionOffset;

        // Skip the question name
        while (recieveData[index] > 0) {
            index++;
        }
        index++;

        // Skip the question type and the question class
        index += 4;

        return index;
    }

    // Create an unsigned 16 bit integer from two bytes in big endian order.
    private static int createNum(byte byte1, byte byte2) {
        return ((byte1 << 8) | byte2);

//        ByteBuffer bb = ByteBuffer.allocate(2); // TODO: check it
//        bb.order(ByteOrder.BIG_ENDIAN);
//        bb.put(baseData[IDoffset]);
//        bb.put(baseData[IDoffset + 1]);
//        short id = bb.getShort(0);
    }

    // Input: b = 01011001, startBit = 3, lastBit = 6
    // Output: 00001100
    private static int createNum(byte b, int startBit, int length) {

        // Shift the byte left so all the bits before the startBit are removed.
        int result = ((b << startBit) & 0xFF);

        // Shift the byte right so all the bits after lastBit are remove and the lastBit located in the 0 index.
        result = result >> (startBit + 7 - length);

        return result;
    }

//    private static String extractDomainName(byte[] data, int offset, int length) {
//
//        // Assume the number of entries in the question section is 1.
//        StringBuilder domainName = new StringBuilder();
//
//        int i = offset; // The question section offset
//
//        while (i < offset + length) {
//
//            // Check if the last two MSB are ones.
//            if ((data[i] & 0b11000000) == 0b11000000) {
//
//                int currIndex = ((data[i] & 0b00111111) << 8) | data[i + 1];
//
//                int currLength = data[currIndex];
//                while (currLength > 0) {
//
//                    for (int j = currIndex + 1; j < currIndex + 1 + currLength; j++) {
//                        domainName.append((char) data[j]);
//                    }
//
//                    currIndex += currLength + 1;
//                    currLength = data[currIndex];
//
//                    if (currLength > 0) {
//                        domainName.append(".");
//                    }
//                }
//
//                i += 2;
//            } else {
//
//                int currLength = data[i];
//
//                for (int j = i + 1; j < i + 1 + currLength; j++) {
//                    domainName.append((char) data[j]);
//                }
//
//                i += currLength + 1;
//            }
//
//            if (i < offset + length - 1) {
//                domainName.append(".");
//            }
//        }
//
//        return domainName.toString();
//    }

}
