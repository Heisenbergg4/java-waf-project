import java.io.BufferedReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.InputStreamReader;

public class WAFTestClient {

    public static void main(String[] args) {
        // Test cases
        testNormalRequest();
        testXSSAttack();
        testSQLInjection();
        testDDoSAttack();
        // Add more test cases as needed
    }

    private static void testNormalRequest() {
        System.out.println("Testing normal request...");
        sendRequest("http://localhost/");
    }

    private static void testXSSAttack() {
        System.out.println("\nTesting XSS attack...");
        sendRequest("http://localhost/?param=<script>alert('XSS')</script>");
    }

    private static void testSQLInjection() {
        System.out.println("\nTesting SQL injection...");
        sendRequest("http://localhost/?param=DROP TABLE users");
    }

    private static void testDDoSAttack() {
        System.out.println("\nTesting DDoS attack...");
        // Simulate a flood of requests using multiple threads
        for (int i = 0; i < 160; i++) {
            new Thread(() -> sendRequest("http://localhost/")).start();
        }
    }


    private static void sendRequest(String urlString) {
        try {
            URL url = new URL(urlString); // URL class
            HttpURLConnection connection = (HttpURLConnection) url.openConnection(); // HttpURLConnection class

            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream())); // BufferedReader, InputStreamReader classes
            String line;
            StringBuilder response = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            System.out.println("Response Body: " + response.toString());
        } catch (IOException e) {
            e.printStackTrace();

        }
    }
}


