package org.daisy.stevin.pcap.util;

public class NoThrow {
    @FunctionalInterface
    public interface NormalFuncNoReturn {
        void invoke() throws Exception;
    }

    @FunctionalInterface
    public interface ExceptionFuncNoReturn {
        void invoke(Exception e);
    }

    public static void executeNoReturn(NormalFuncNoReturn func1, ExceptionFuncNoReturn func2) {
        try {
            func1.invoke();
        } catch (Exception e) {
            e.printStackTrace();
            func2.invoke(e);
        }
    }

    @FunctionalInterface
    public interface NormalFunc<T> {
        T invoke() throws Exception;
    }

    @FunctionalInterface
    public interface ExceptionFunc<T> {
        T invoke(Exception e);
    }

    public static <T> T execute(NormalFunc<T> func1, ExceptionFunc<T> func2) {
        try {
            return func1.invoke();
        } catch (Exception e) {
            e.printStackTrace();
            return func2.invoke(e);
        }
    }

}
