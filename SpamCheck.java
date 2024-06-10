import java.net.*;
import java.util.Scanner;
import java.util.regex.Pattern;

public class SpamCheck {
    
    public static final String BANNER = """
    +---------------------------------------------------------+
    |                       SpamCheck                         |
    |                       =========                         |
    |               Author: Prashant Bhandari                 |
    +---------------------------------------------------------+
    | This Program is designed to check whether a given list  |
    | of IP addresses belongs to known spammers or legitimate |
    | sources. It does this by querying the Spamhaus Block    |
    | List (SBL) to determine if an IP address is listed as a |
    | spam source.                                            |
    +---------------------------------------------------------+
    
    Usage: java SpamCheck [IP_ADDRESS]...
        
    You can provide multiple IP addresses separated by spaces.

    Example:
        java SpamCheck 192.168.1.1 8.8.8.8 127.0.0.1
    """;

    public static final String BLACKHOLE = "zen.spamhaus.org";

    // ANSI escape codes for text formatting
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_RESET = "\u001B[0m";

    private static boolean isValidIP(String ip) {
        String zeroTo255 = "([0-9]{1,2}|1[0-9]{2}|2[0-4][0-9]|25[0-5])";
        String regex = zeroTo255 + "\\." + zeroTo255 + "\\." + zeroTo255 + "\\." + zeroTo255;
        Pattern pattern = Pattern.compile(regex);
        return pattern.matcher(ip).matches();
    }

    private static boolean isSpammer(String ip) {
        try {
            InetAddress address = InetAddress.getByName(ip);
            byte[] quad = address.getAddress();
            String query = BLACKHOLE;
            for (byte octet : quad) {
                int unsignedByte = octet < 0 ? octet + 256 : octet;
                query = unsignedByte + "." + query;
            }
            InetAddress.getByName(query);
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public static void main(String[] args) {
        System.out.println(BANNER);
        if (args.length == 0) {
            System.out.println("No IP addresses provided as arguments. Please enter IP addresses interactively.");
            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter IP addresses separated by spaces:");
            String input = scanner.nextLine();
            args = input.split("\\s+");
        }
        System.out.println();
        System.out.printf(" %17s ║ %s\n", "Host", "Status");
        System.out.println("═══════════════════╬════════════");
        for (String ip : args) {
            if (isValidIP(ip)) {
                if (isSpammer(ip)) {
                    System.out.printf(" %s%17s%s ║ %s%s%s\n", ANSI_BLUE, ip, ANSI_RESET, ANSI_RED, "Spammer", ANSI_RESET);
                } else {
                    System.out.printf(" %s%17s%s ║ %s%s%s\n", ANSI_BLUE, ip, ANSI_RESET, ANSI_GREEN, "Legitimate", ANSI_RESET);
                }
            } else {
                System.out.printf(" %s%17s%s ║ %s%s%s\n", ANSI_BLUE, ip, ANSI_RESET, ANSI_RED, "Invalid IP", ANSI_RESET);
            }
        }
        System.out.println("\nThank you for using SpamCheck!");
    }
}
