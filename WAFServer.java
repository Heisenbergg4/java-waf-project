import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class WAFServer {

    private static final int PORT = 80;
    private static final List<String> BLOCKED_PATTERNS = new ArrayList<>();
    private static final Set<String> BLACKLISTED_IPS = new HashSet<>();
    private static final Map<String, AtomicInteger> REQUEST_COUNT = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_SECOND = 10;

    public static void main(String[] args) {
        // Add your security rules (patterns) to the list
        BLOCKED_PATTERNS.add("<script>"); // Basic XSS check
        BLOCKED_PATTERNS.add("DROP TABLE"); // Basic SQL injection check

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("WAF Server listening on port " + PORT);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress());

                // Check for blacklisted IP
                if (BLACKLISTED_IPS.contains(clientSocket.getInetAddress().getHostAddress())) {
                    System.out.println("IP blacklisted. Rejecting connection.");
                    clientSocket.close();
                    continue;
                }

                // Rate limiting
                String clientAddress = clientSocket.getInetAddress().getHostAddress();
                AtomicInteger count = REQUEST_COUNT.computeIfAbsent(clientAddress, k -> new AtomicInteger(0));
                if (count.incrementAndGet() > MAX_REQUESTS_PER_SECOND) {
                    System.out.println("Rate limit exceeded. Rejecting connection.");
                    BLACKLISTED_IPS.add(clientAddress); // Add to blacklist
                    clientSocket.close();
                    continue;
                }

                // Handle request in a separate thread
                new Thread(new WAFRequestHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static List<String> getBlockedPatterns() {
        return BLOCKED_PATTERNS;
    }

    public static Set<String> getBlacklistedIps() {
        return BLACKLISTED_IPS;
    }
}

class WAFRequestHandler implements Runnable {

    private final Socket clientSocket;

    public WAFRequestHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try {
            handleRequest(clientSocket);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void handleRequest(Socket clientSocket) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        OutputStream outputStream = clientSocket.getOutputStream();

        StringBuilder requestBuilder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            requestBuilder.append(line).append("\r\n");
        }
        String request = requestBuilder.toString();
        System.out.println("Request: " + request);

        // Check for blocked patterns
        if (containsBlockedPattern(request)) {
            // Add the IP to the blacklist
            String clientAddress = clientSocket.getInetAddress().getHostAddress();
            WAFServer.getBlacklistedIps().add(clientAddress);
            // If a blocked pattern is found, send a forbidden response
            String forbiddenResponse = "HTTP/1.1 403 Forbidden\r\n\r\nBlocked by WAF";
            outputStream.write(forbiddenResponse.getBytes());
        } else {
            // Otherwise, process the request and send a normal response
            String okResponse = "HTTP/1.1 200 OK\r\n\r\n";
            outputStream.write(okResponse.getBytes());
        }

        outputStream.flush();
        reader.close();
        outputStream.close();
        clientSocket.close();
    }

    private boolean containsBlockedPattern(String request) {
        List<String> blockedPatterns = WAFServer.getBlockedPatterns();
        for (String pattern : blockedPatterns) {
            if (request.contains(pattern)) {
                return true;
            }
        }
        return false;

    }
}
