package il.ac.idc.cs.sinkhole;

/*
    from the course book:  Computer Networking: A Top Down Approach, by Kurose and Ross
 */
import java.io.*;
import java.net.*;
import java.util.Arrays;

class UDPClient
{
    public static void main(String[] args) throws Exception
    {
        BufferedReader inFromUser =
                new BufferedReader(new InputStreamReader(System.in));
        DatagramSocket clientSocket = new DatagramSocket();
        InetAddress IPAddress = InetAddress.getByName("127.0.0.1");
        byte[] sendData;
        byte[] receiveData = new byte[1024];
        String sentence = inFromUser.readLine();
        sendData = sentence.getBytes();
        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, 9876);

        clientSocket.send(sendPacket);

        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

        clientSocket.receive(receivePacket);

        String modifiedSentence = new String(Arrays.copyOfRange(receivePacket.getData(), 0, receivePacket.getLength()));
        System.out.println("FROM SERVER: " + modifiedSentence);

        clientSocket.close();
    }
}
