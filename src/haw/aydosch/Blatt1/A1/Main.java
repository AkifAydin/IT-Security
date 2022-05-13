package haw.aydosch.Blatt1.A1;

import java.util.HashSet;

public class Main {
    public static void main(String[] args) {
        LCG chiang_hwang_kao = new LCG(1, 19496, 0, (int)(Math.pow(2, 15)-19));     // Chiang, Hwang, Kao
        LCG BASIC = new LCG(1, 214013, 13523655, (int)Math.pow(2, 24));             // BASIC
        LCG QBasic = new LCG(1, 16598013, 12820163, (int)Math.pow(2, 24));          // QBasic

        HashSet<Integer> numbers = new HashSet<>();

        for(int i = 0; i < 256; i++) {
            numbers.add(chiang_hwang_kao.nextInt() & 0xFF);
        }

        System.out.println(numbers.size());
    }
}
