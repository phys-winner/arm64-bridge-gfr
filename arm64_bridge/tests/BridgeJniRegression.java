public final class BridgeJniRegression {
    private static native void run();
    public static byte byteValue() { return -7; }
    public static char charValue() { return '\uf123'; }
    public static short shortValue() { return -1234; }
    public static float floatValue(float x) { return x * 2; }
    public static long mixed(int i, float f, long l, double d) {
        return i == 7 && f == 1.25f && d == 3.5 ? l : -1;
    }
    public static void main(String[] args) {
        System.load(args[0]);
        run();
        System.out.println("PASS real ART JNI regression");
    }
}
