package il.ac.idc.cs.sinkhole;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class DnsParser {

    final int QRoffset = 2;
    final int RcodeOffset = 3;
    final int ANCountOffset = 6;
    final int NSCountOffset = 8;
    final int SectionQuestionOffset = 12;

    private byte[] data;

    DnsParser(byte[] data) {
        this.data = data;
    }

    byte[] getData() {
        return this.data;
    }

    void setData(byte[] data) {
        this.data = data;
    }

    int getID() {
        return createNum(data[0], data[1]);
    }

    // response code (RCODE) is 0 if there is no error
    int getResponseCode() {
        return createNum(data[RcodeOffset], 4, 4);
    }

    // ANCOUNT = an unsigned 16 bit integer specifying the number of resource records in the answer section.
    int getAnswerCount() {
        return createNum(data[ANCountOffset], data[ANCountOffset + 1]);
    }

    // NSCOUNT = an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
    int getNameServerCount() {
        return createNum(data[NSCountOffset], data[NSCountOffset + 1]);
    }

    String getQuestionName() {

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

    String getResourceName() {
        int index = skipQueriesSection();

        index = skipToResourceLength(index);

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

    void changeHeaderFlags(byte responseCode) {

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

    boolean isResponse() {
        return (data[QRoffset] & 0b10000000) != 0;
    }

    private int skipToResourceLength(int index) {

        // Skip the domain name to which this resource record pertains.
        // Check if the last two MSB are ones.
        if ((data[index] & 0b11000000) == 0b11000000) {
            index+= 2;
        }
        else {
            while (data[index] != 0) {
                index++;
            }
            index++;
        }

        // Skip Type, Class and TTL (notice that TTL is 4 bytes)
        index += 8;

        return index;
    }

    private int skipQueriesSection() {

        int index = SectionQuestionOffset;

        // Skip the question name
        while (data[index] > 0) {
            index++;
        }
        index++;

        // Skip the question type and the question class
        index += 4;

        return index;
    }

    // Create an unsigned 16 bit integer from two bytes in big endian order.
    private int createNum(byte byte1, byte byte2) {

        // return (((byte1 << 8) & 0xFFFF) | byte2);

        ByteBuffer bb = ByteBuffer.allocate(2); // TODO: check it
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.put(byte1);
        bb.put(byte2);
        short id = bb.getShort(0);
        // convert id to unsigned 16-bit
        return id & 0xFFFF;
    }

    // Input: b = 01011001, startBit = 3, lastBit = 6
    // Output: 00001100
    private int createNum(byte b, int startBit, int length) {

        // Shift the byte left so all the bits before the startBit are removed.
        int result = ((b << startBit) & 0xFF);

        // Shift the byte right so all the bits after lastBit are remove and the lastBit located in the 0 index.
        result = result >> (startBit + 7 - length);

        return result;
    }
}
