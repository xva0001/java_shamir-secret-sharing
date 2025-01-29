import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class randomBytes {

    public static byte[] getRandombtyes(int n) {

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[n];
        random.nextBytes(bytes);
        return bytes;
    }

    public static byte[] getRandomBytes(int numBytes) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[numBytes];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static int[] byteArrayToIntArray(byte[] byteArray) {
        int[] intArray = new int[byteArray.length / 4];
        ByteBuffer byteBuffer = ByteBuffer.wrap(byteArray);

        for (int i = 0; i < intArray.length; i++) {
            intArray[i] = byteBuffer.getInt();
        }
        return intArray;
    }

    public static void main(String[] args) {
        // byte[] byteArray = {0, 0, 0, 1, 0, 0, 0, 2}; // Example byte array
        // int[] intArray = byteArrayToIntArray(byteArray);

        // for (int i : intArray) {
        // System.out.println(i); // Should print 1 and then 2
        // }

        int[] intArray = { 1, 2, 3, 4, 5 }; // Example integer array
        byte[] byteArray = intArrayToByteArray(intArray);

        // Print the byte array
        System.out.println(Arrays.toString(byteArray));
    }

    public static byte[] intArrayToByteArray(int[] intArray) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(intArray.length * 4);
        for (int i : intArray) {
            byteBuffer.putInt(i);
        }
        return byteBuffer.array();
    }

    public static byte[] stringToBytes(String str) {
        return str.getBytes();
    }

    public static String bytesToString(byte[] byteArray) {
        return new String(byteArray);
    }

      public static byte[] intArrayToByteArray_pure_no_padding(int[] intArray) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (int i : intArray) {
            while ((i & 0xFFFFFF80) != 0L) {
                byteArrayOutputStream.write((i & 0x7F) | 0x80);
                i >>>= 7;
            }
            byteArrayOutputStream.write(i & 0x7F);
        }
        return byteArrayOutputStream.toByteArray();
    }

}
