package haw.aydosch.Blatt1.A1;

public class LCG {
    private int x;
    private final long a;
    private final long b;
    private final long m;

    public LCG(int x_0, int a, int b, int m) {
        this.x = x_0;
        this.a = a;
        this.b = b;
        this.m = m;
    }

    public int nextInt() {
        // Compute random num
        long x_next = (this.a * this.x + this.b) % this.m;

        // Increase x for next computation
        this.x += 1;

        return (int)x_next;
    }
}
