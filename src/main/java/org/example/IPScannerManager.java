package org.example;

import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class IPScannerManager {
    private final String[] ipAddresses; // Массив IP-адресов для сканирования
    private final int numThreads; // Количество потоков для сканирования
    private final ExecutorService executorService;

    public IPScannerManager(String[] ipAddresses, int numThreads) {
        this.ipAddresses = ipAddresses;
        this.numThreads = numThreads;
        this.executorService = Executors.newFixedThreadPool(numThreads);
    }

    public void startScanning() {
        int addressesPerThread = ipAddresses.length / numThreads;

        for (int i = 0; i < numThreads; i++) {
            int startIdx = i * addressesPerThread;
            int endIdx = (i == numThreads - 1) ? ipAddresses.length : startIdx + addressesPerThread;
            String[] addressesToScan = Arrays.copyOfRange(ipAddresses, startIdx, endIdx);

            Runnable task = new IPScannerTask(addressesToScan);
            executorService.execute(task);
        }

        executorService.shutdown();
        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static void main(String[] args) {
        String[] ipAddresses = {"example1.com", "example2.com", "example3.com"}; // Замените на список IP-адресов
        int numThreads = 2; // Количество потоков

        IPScannerManager manager = new IPScannerManager(ipAddresses, numThreads);
        manager.startScanning();
    }
}
