package il.ac.idc.cs.sinkhole;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/*
    DnsParser - the class receives a byte array of a DNS packet and allows
    to extract many fields like: QDCOUNT, ANCOUNT, QNAME, RDATA and etc.
 */
class DnsParser {

    private final int QRoffset = 2;
    private final int RcodeOffset = 3;
    private final int SectionQuestionOffset = 12;
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
        return data[RcodeOffset] & 0xF;
    }

    // ANCOUNT = an unsigned 16 bit integer specifying the number of resource records in the answer section.
    int getAnswerCount() {
        int ANCountOffset = 6;
        return createNum(data[ANCountOffset], data[ANCountOffset + 1]);
    }

    // NSCOUNT = an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
    int getNameServerCount() {
        int NSCountOffset = 8;
        return createNum(data[NSCountOffset], data[NSCountOffset + 1]);
    }

    String getQuestionName() {

        // Assume the number of entries in the question section is 1,
        // and the domain name is compressed by type of a sequence of labels ending in a zero octet
        return readSequenceOfLabelsUntilZero(SectionQuestionOffset);
    }

    String getResourceName() {

        int index = SectionQuestionOffset;

        // Skip the question name (we assume there is only one question).
        index = skipDomainName(index);

        // Skip the question type and the question class
        index += 4;

        // Skip the name of the first authoritative name server
        index = skipDomainName(index);

        // Skip Type, Class, TTL and RDLENGTH (notice that TTL is 4 bytes)
        index += 10;

        // Read the RDATA field of the first authoritative name server
        return readDomainName(index);
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

    // Skip the domain name to which this resource record pertains.
    private int skipDomainName(int index) {

        // Check if the compression schema is a pointer.
        if (isPointer(data[index])) {
            index += 2;
        }
        // Otherwise, the compression schema starts with a sequence of labels.
        else {
            while (data[index] != 0 && !isPointer(data[index])) {
                int currLength = data[index];
                index += (1 + currLength);
            }

            // Check if the compression type ends with a zero octet or a pointer
            if (data[index] == 0) {
                index++; // Skip the zero octet
            } else {
                index += 2; // Skip the 2-byte pointer
            }
        }

        return index;
    }

    private String readDomainName(int offset) {

        StringBuilder domainName = new StringBuilder();

        int i = offset;

        // Check if the compression type is a pointer
        if (isPointer(data[i])) {

            int currIndex = getPointerOffset(i);// ((data[i] & 0b00111111) << 8) | data[i + 1];
            String subDomainName = readSequenceOfLabelsUntilZero(currIndex);
            domainName.append(subDomainName);
        } else {

            // Otherwise, the compression type starts with a sequence of labels.
            while (data[i] != 0 && !isPointer(data[i])) {

                int currLength = data[i];

                for (int j = i + 1; j < i + 1 + currLength; j++) {
                    domainName.append((char) data[j]);
                }

                i += currLength + 1;

                if (data[i] != 0 && !isPointer(data[i])) {
                    domainName.append(".");
                }
            }

            // Check if the compression type ends with a pointer
            if (isPointer(data[i])) {

                domainName.append(".");
                int currIndex = getPointerOffset(i); // ((data[i] & 0b00111111) << 8) | data[i + 1];
                String subDomainName = readSequenceOfLabelsUntilZero(currIndex);
                domainName.append(subDomainName);
            }
        }

        return domainName.toString();
    }

    // Side effect - advance the index parameter
    private String readSequenceOfLabelsUntilZero(Integer index) {

        StringBuilder domainName = new StringBuilder();

        int curLength = data[index];

        while (curLength != 0) {

            for (int j = index + 1; j < index + 1 + curLength; j++) {
                domainName.append((char) data[j]);
            }

            index += curLength + 1;
            curLength = data[index];

            if (curLength > 0) {
                domainName.append(".");
            }
        }

        return domainName.toString();
    }

    private int getPointerOffset(int index) {
        return ((data[index] & 0b00111111) << 8) | data[index + 1];
    }

    private boolean isPointer(byte b) {
        // Check if the two last msb are ones
        return (b & 0b11000000) == 0b11000000;
    }

    // Create an unsigned 16 bit integer from two bytes in big endian order.
    private int createNum(byte byte1, byte byte2) {

        ByteBuffer bb = ByteBuffer.allocate(2);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.put(byte1);
        bb.put(byte2);
        short id = bb.getShort(0);
        // convert id to unsigned 16-bit
        return id & 0xFFFF;
    }
}