import java.math.BigInteger;
import java.util.ArrayList;

import org.w3c.dom.ranges.RangeException;

/**
 * shamir-secret-sharing was rewritten with Java.
 * purpose : to understand the algorithm and to implement it in Java.
 * 
 * @author xva0001
 * @version 1.0
 *          reference : https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
 *          code reference :
 *          https://github.com/privy-io/shamir-secret-sharing/blob/main/src/index.ts
 */

public class ShamirSecretSharing {

    // The Polynomial used is: x⁸ + x⁴ + x³ + x + 1
    //
    // Lookup tables pulled from:
    //
    // *
    // https://github.com/hashicorp/vault/blob/9d46671659cbfe7bbd3e78d1073dfb22936a4437/shamir/tables.go
    // * http://www.samiam.org/galois.html
    //
    // 0xe5 (229) is used as the generator.

    // Provides log(X)/log(g) at each index X.

    static final int[] LOG_TABLE = {
            0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
            0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
            0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
            0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
            0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4, 0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
            0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13, 0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
            0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12, 0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
            0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56, 0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
            0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3, 0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
            0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf, 0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
            0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67, 0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
            0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34, 0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
            0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7, 0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
            0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a, 0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
            0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c, 0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
            0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0, 0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38,
    };

    // Provides the exponentiation value at each index X.
    static final int[] EXP_TABLE = {
            0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
            0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
            0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
            0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d, 0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
            0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f, 0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
            0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85, 0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
            0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
            0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
            0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
            0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
            0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84, 0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
            0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2, 0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
            0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c, 0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
            0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
            0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
            0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01,
    };

    // define operation for GF(2^8) field
    // --------------------------------------------------------------------------------------------

    // This can be used for both addition and subtraction.
    // IN GF , addition and subtraction are the same operation.
    static int addOrSubtract(int a, int b) throws RangeException {
        if (a < 0 || a > 255 || b < 0 || b > 255) {
            throw new RangeException((short) 0, "number(s) is(are) out of range");
        }
        return a ^ b;
    }

    // divides two numbers in GF(2^8).
    static int divide(int a, int b) throws RangeException, ArithmeticException {
        if (a < 0 || a > 255 || b < 0 || b > 255) {
            throw new RangeException((short) 0, "number(s) is(are) out of range");
        }
        if (b == 0) {
            throw new ArithmeticException("division by zero");
        }
        if (a == 0) {
            return 0;
        }
        int logA = LOG_TABLE[a];
        int logB = LOG_TABLE[b];
        /**
         * array index starts from 0, so the diff need to limit between 0 - 254. //0
         * wiil be retured (look the line 84)
         */
        int diff = (logA - logB + 255) % 255; // calculate the difference // + 255 to avoid negative values
        return EXP_TABLE[diff];
    }

    static int multiply(int a, int b) throws RangeException {
        if (a < 0 || a > 255 || b < 0 || b > 255) {
            throw new RangeException((short) 0, "a:"+a+", b:"+b+", "+"number(s) is(are) out of range");
        }
        if (a == 0 || b == 0) {
            return 0;
        }
        int logA = LOG_TABLE[a];
        int logB = LOG_TABLE[b];
        int sum = (logA + logB) % 255;
        return EXP_TABLE[sum];
    }
    // --------------------------------------------------------------------------------------------
    // end of GF(2^8) operations

    // interploate the polynomial
    static int interpolate(int x, int[] xCoords, int[] yCoords) throws RangeException {
        if (xCoords.length != yCoords.length) {
            throw new RangeException((short) 0, "xCoords and yCoords must have the same length");
        }
        int result = 0;
        for (int i = 0; i < xCoords.length; i++) {
            int basis = 1;
            for (int j = 0; j < xCoords.length; j++) {
                if (i == j) {
                    continue;
                }

                int xj = xCoords[j];
                int xi = xCoords[i];
                int number = addOrSubtract(x, xj); // (x - xn)
                int den = addOrSubtract(xi, xj); // (x(n-1) - xn)
                int term = divide(number, den); // (x - xn)/(x(n-1) - xn)
                basis = multiply(basis, term); // lagrange basis // Ln(x) = (x - x0)/(xi - x0) * (x - x1)/(xi - x1) *
                                               // ... * (x - xn)/(xi - xn)

            }
            result = addOrSubtract(result, multiply(yCoords[i], basis));// f(x) = y0 * L0(x) + y1 * L1(x) + ... + yn *
                                                                        // Ln(x)
        }
        return result;
    }

    // Horner's method
    static int evaluate(int[] coff, int x, int degree) throws RangeException, ArrayIndexOutOfBoundsException {
        if (x == 0) {
            throw new RangeException((short) 0, "x must not be 0");
        }
        int result = 0;
        try {
            result = coff[degree];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new RangeException((short) 0, "degree must be less than coff.length");

        }
        for (int i = degree - 1; i >= 0; i--) {
            int coeff = coff[i]; // get the coefficient
            result = addOrSubtract(multiply(result, x), coeff);
        }
        return result;
    }

    /**
     * 
     * @param intercept : the point where the polynomial crosses the y-axis
     * @param degree
     * @return
     */

     public static int[] newCoefficients(int intercept, int degree) {
        int[] coefficients = new int[degree + 1];
        coefficients[0] = intercept;
        byte[] randomBytes_ = randomBytes.getRandomBytes(degree);
        coefficients[0] = intercept;
        for (int i = 0; i < degree; i++) {
            coefficients[i + 1] = randomBytes_[i] & 0xFF; // Convert byte to int
        }
        return coefficients;
    }

    static int[] newCoordinates() {
                // Pseudo-randomize the array of coordinates.
        //
        // This impl maps almost perfectly because both of the lists (coordinates and
        // randomIndices)
        // have a length of 255 and byte values are between 0 and 255 inclusive. The
        // only value that
        // does not map neatly here is if the random byte is 255, since that value used
        // as an index
        // would be out of bounds. Thus, for bytes whose value is 255, wrap around to 0.
        //
        // WARNING: This shuffle is biased and should NOT be used if an unbiased shuffle
        // is required.
        //
        // However, Shamir-based secret sharing does not require any particular indexing
        // (shuffled or
        // not) for its security properties to hold; this means including the biased
        // shuffle is not
        // itself problematic here.
        // conlusion: the shuffle (order) is biased but it is not a problem for the
        // algorithm.
        int[] coords = new int[255];
        for (int i = 0; i < 255; i++) {
            coords[i] = i + 1;
        }

        int[] randomIndices = randomBytes.byteArrayToIntArray(randomBytes.getRandombtyes(255 * 4));
        for (int i = 0; i < 255; i++) {
            int j = randomIndices[i] % 255 ; // limit the value to 0 - 254
            if (j<0) {
                j += 255;
            }
            int temp = coords[i];
            // System.out.print(i);
            // System.out.print(j);
            coords[i] = coords[j];
            coords[j] = temp;
        }
        return coords;
    }

    static int[][] split( byte[] secretArr,int shares, int threshold) throws Exception {
        if (shares <= 1 || shares > 255) {
            throw new Exception("shared must be between 2 and 255");
        }
        if (threshold < 2 || threshold > 255) {
            throw new Exception("threshold must be between 2 and 255");
            
        }
        if (threshold > shares) {
            throw new Exception("threshold must be less than or equal to shared");
        }

        long secretBytesLen = secretArr.length;
        int[] xCoords = newCoordinates();
        ArrayList<int[]> res = new ArrayList<>();

        for (int i = 0; i < shares; i++) {        
            int[] share =  new int[secretArr.length+1];
            share[secretArr.length] = xCoords[i];
            res.add(share);
        }
        int degree = threshold - 1;

        for (int i = 0; i < secretArr.length; i++) {
            int[] coff = newCoefficients(secretArr[i], degree);

            for (int j = 0; j < shares; j++) {

                int x = xCoords[j];
                int y = evaluate(coff, x, degree);
                res.get(j)[i] = y;
            }
        }
        return res.toArray(new int[res.size()][secretArr.length+1]);
    }

    static byte[] combine(int[][] shares) throws Exception {
        if (shares.length < 2) {
            throw new Exception("shares must be at least 2");
        }
        int threshold = shares[0].length;
        for (int i = 1; i < shares.length; i++) {
            if (shares[i].length != threshold) {
                throw new Exception("all shares must have the same length");
            }
        }
        int sharesLen = shares.length;
        int shareLen = shares[0].length;
        int secretLen = shareLen - 1;
        int[] secret = new int[secretLen];

        int[] xCoords = new int[sharesLen];
        int[] yCoords = new int[sharesLen];

        ArrayList<Integer> samples = new ArrayList<>();
        for (int i = 0; i < sharesLen; i++) {
            int[] share = shares[i];
            int sample = share[shareLen-1];
            if (samples.contains(sample)) {
                throw new Exception("duplicate share detected");
            }
            samples.add(sample);
            xCoords[i] = sample;
        }

        for (int i = 0; i < secretLen; i++) {
            for (int j = 0; j < sharesLen; j++) {

                yCoords[j] = shares[j][i];
            }
            secret[i] = interpolate(0, xCoords, yCoords);
        }
        
        return randomBytes.intArrayToByteArray(secret);  //for non-ascii
    }


    public static void main(String[] args) throws Exception {

        // int[] x = {7,3,2,1};
        // int[] y = {5,6,7,8};

        // System.out.println(interpolate(0, x, y));
        // System.out.println("\nNext Test");
        // System.out.println(evaluate(x, 4,3));

        // System.exit(0);

        String hiWorld = "Hello World!";
        /**
         * 
72
101
108
108
111
32
87
111
114
108
100
33



72

101

108

108

111

32

87

111

114

108

100

33
         */
        byte[] bytex_str = randomBytes.stringToBytes(hiWorld);
        byte[] bytex_str2 = randomBytes.stringToBytes(hiWorld+"");
        try{
            var secret = split(bytex_str, 4, 2);
            var secret2 = split(bytex_str2, 4, 2);

            int[][] s = {secret[0],secret2[0]};

            System.out.println(secret);
            //test ok
            var text = combine(secret);
            System.out.println("combine : "+randomBytes.bytesToString(text));
            //test fail
            var text2 = combine(s);
            System.out.println("combine FAIL : "+randomBytes.bytesToString(text2));

            
            

            // for (byte b : text) {

            //     System.err.println(b);
                
            // }

            // System.out.println("\n");

            // for (byte b : bytex_str) {
            //     System.out.println(b);
            // }

            // System.out.println();

        }catch(Exception e){
            throw e;
            
        }
    }
}