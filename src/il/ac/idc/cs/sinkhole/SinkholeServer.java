package il.ac.idc.cs.sinkhole;

import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class SinkholeServer
{
    public static void main(String[] args)
    {
        try {

            if (args.length > 1) {
                System.err.println("Usage: il.ac.idc.cs.sinkhole.SinkholeServer [blocklist-path]");
                return;
            }

            Set<String> blockList = null;
            if (args.length == 1) {
                List<String> lines = Files.readAllLines(Path.of(args[0]));
                blockList = new HashSet<>(lines);
            }

            Random rnd = new Random();
            final int maxIterations = 16;
            final List<String> rootServers = Stream.of("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m")
                    .map(x -> x.concat(".root-servers.net")).collect(Collectors.toList());
            final int dnsPort = 53;
            final int bufSize = 1024;
            final int QRoffset = 2;
            final int RcodeOffset = 3;
            final int ANCountOffset = 6;
            final int NSCountOffset = 8;
            final int SectionQuestionOffset = 12;

            // The DNS server listen on port 5300
            DatagramSocket serverSocket = new DatagramSocket(5300);

            while (true) {

                byte[] receiveData = new byte[bufSize];
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

                // Blocks until datagram received from the client
                serverSocket.receive(receivePacket);

                String domainName = extractDomainName(receiveData, SectionQuestionOffset);

                // Check if the domain name that needs to be resolved is in the specified block list
                if (blockList != null && blockList.contains(domainName)) {

                    // Change QR to one to indicate the message is a response // TODO: maybe I don't need to set it in this case
                    byte qr = (byte)(receiveData[QRoffset] | 0b10000000);
                    receiveData[QRoffset] = qr;

                    // change response code to NXDOMAIN error
                    byte rcode = (byte)(receiveData[RcodeOffset] | 0b000000011);
                    receiveData[RcodeOffset] = rcode;

                    DatagramPacket sendPacket = new DatagramPacket(receiveData, receivePacket.getLength(), receivePacket.getAddress(), receivePacket.getPort());
                    serverSocket.send(sendPacket);
                    continue;
                }

                // Assume the number of entries in the question section is 1.

                // Send the DNS query to a randomly chosen root server
                int randomIndex = rnd.nextInt(rootServers.size());
                String rootServer = rootServers.get(randomIndex);
                InetAddress IPAddress = InetAddress.getByName(rootServer);

                byte[] sendData = new byte[bufSize];
                System.arraycopy(receiveData, 0, sendData, 0, bufSize);

                DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, dnsPort);
                serverSocket.send(sendPacket);

                serverSocket.receive(sendPacket);

                // response code (RCODE) is 0 if there is no error
                int responseCode = createNum(sendData[RcodeOffset], 4, 4);

                // ANCOUNT = an unsigned 16 bit integer specifying the number of resource records in the answer section.
                int answerCount = createNum(sendData[ANCountOffset], sendData[ANCountOffset + 1]);

                // NSCOUNT = an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
                int nameServerCount = createNum(sendData[NSCountOffset], sendData[NSCountOffset + 1]);

                int iteration = 0;

                while (responseCode == 0 && answerCount == 0 && nameServerCount > 0 && iteration < maxIterations) {

                    // Send the query to the first name server in the AUTHORITY section

                    // Read the RDATA
                    int index = SectionQuestionOffset;
                    int currLength = sendData[index];
                    while (currLength > 0) {

                        index += currLength + 1;
                        currLength = sendData[index];
                    }

                    index++;

                    // Skip 4 bytes of QTYPE and QCLASS
                    index += 4;

                    // Skip to RDATA
                    currLength = sendData[index];

                    while(sendData[index] != 0){
                        index++;
                    }

                    index++;

                    // Skip 8 bytes of type, class and ttl.
                    index+=8;

                    index--; // tODO: why

                    int resourceLength = createNum(sendData[index], sendData[index + 1]);

                    index += 2;


                    String nameServer = extractDomainName(sendData, index);

                    IPAddress = InetAddress.getByName(nameServer);

                    System.arraycopy(receiveData, 0, sendData, 0, bufSize);
                    sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, dnsPort);

                    serverSocket.send(sendPacket);

                    serverSocket.receive(sendPacket);

                    iteration++;

                    // response code (RCODE) is 0 if there is no error
                    responseCode = createNum(sendData[RcodeOffset], 4, 4);

                    // ANCOUNT = an unsigned 16 bit integer specifying the number of resource records in the answer section.
                    answerCount = createNum(sendData[ANCountOffset], sendData[ANCountOffset + 1]);

                    // NSCOUNT = an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
                    nameServerCount = createNum(sendData[NSCountOffset], sendData[NSCountOffset + 1]);
                }

                // send the final response to the client




//            String sentence = new String(Arrays.copyOfRange(receivePacket.getData(), 0, receivePacket.getLength()));
//            System.out.println("RECEIVED: " + sentence);
//            InetAddress IPAddress = receivePacket.getAddress();
//            int port = receivePacket.getPort();
//            String capitalizedSentence = sentence.toUpperCase();
//
//            sendData = capitalizedSentence.getBytes();
//
//            DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, port);
//            serverSocket.send(sendPacket);
            }
        }
        catch (Exception ex) {
            System.err.println(ex.getMessage());
        }
    }

    // Create an unsigned 16 bit integer from two bytes in big endian order.
    private static int createNum(byte byte1, byte byte2) {
        return ((byte1 << 8) | byte2);
    }

    // Input: b = 01011001, startBit = 3, lastBit = 6
    // Output: 00001100
    private static int createNum(byte b, int startBit, int lastBit)
    {
        // Shift the byte left so all the bits before the startBit are removed.
        int result = ((b << startBit) & 0xFF);

        // Shift the byte right so all the bits after lastBit are remove and the lastBit located in the 0 index.
        result = result >> (startBit + 7 - lastBit);

        return result;
    }

    private static String extractDomainName(byte[] data, int offset) {

        // Assume the number of entries in the question section is 1.
        StringBuilder domainName = new StringBuilder();

        int i = offset; // The question section offset
        int length = data[i];



        // Check if the last two MSB are ones.
        if ((length & 0b11000000) == 0b11000000) {
            int offset123 = ((data[i] & 0b00111111) << 8) | data[i+1];

            i = offset123;
            length = data[i];

            offset123++;

            for (int j = offset123; j < offset123 + length; j++) {
                domainName.append((char)data[j]);
            }
        }
        else {
            while (length > 0) {

                i++;

                for (int j = i; j < i + length; j++) {
                    domainName.append((char)data[j]);
                }

                i += length;
                length = data[i];

                if (length > 0) {
                    domainName.append(".");
                }
            }
        }

        return domainName.toString();
    }

}
