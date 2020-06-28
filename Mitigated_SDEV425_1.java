/*
 * Name: Gabrielle Jeuck
 * Class: SDEV 425
 * Date: 6/21/2020
 * Project: Homework 1 - SDEV425_1 Mitigation.  User Input validation. 
 */
package mitigated_sdev425_1;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author gwins
 */
public class Mitigated_SDEV425_1 {

    // variables - patterns and whitelisted path for file 
    private static final Pattern CHARACTER_PATTERN = Pattern.compile("[^A-Za-z0-9\\s_.-]",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[a-z0-9._%+-]+"
            + "@[a-z0-9.-]+\\.[a-z]{2,3}", Pattern.CASE_INSENSITIVE);
    private static final String WHITELISTED_PATH = "C:\\EmailFile";
    private static Matcher matcher;
    private static String fileName;
    private static String fileLine;
    private static FileInputStream inputStream;
    private static BufferedReader reader;

    /**
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {
        // checks to see if args is empty
        if (args.length > 0 && args[0] != null) {
            // normalize user input
            fileName = Normalizer.normalize(args[0], Form.NFKC);
            // validates to check if file name has malicious characters  
            // or path directory doesn't match
            matcher = CHARACTER_PATTERN.matcher(fileName);
            if (matcher.find() || !validatePath(fileName)) {
                System.out.println("Check file name in arguments and try again.");

            } else {
                // if file has been validated 
                // this tries to read file and catches exceptions
                try {
                    inputStream = new FileInputStream(fileName);
                    reader = new BufferedReader(new InputStreamReader(inputStream));

                    System.out.println("Email Addresses: ");
                    // Read one Line using BufferedReader
                    while ((fileLine = reader.readLine()) != null) {
                        fileLine = Normalizer.normalize(fileLine, Form.NFKC);
                        if (validEmail(fileLine)) {
                            System.out.println(fileLine);
                        }
                    }
                } finally {
                    // Need another catch for closing the streams
                    try {
                        if (inputStream != null) {
                            inputStream.close();
                        }
                    } catch (IOException io) {
                        System.out.println("Invalid File.");
                        return;
                    }
                }
            }
        } else {
            System.out.println("Please check arguments and provide file name");
        }
    }

    // validates file is within the accepted whitelisted path returns true or false
    private static boolean validatePath(String fileName) {
        File file = new File(fileName);
        String canonicalPath = null;
        try {
            canonicalPath = file.getCanonicalPath();
            // makes sure specific document is what's being used instead of 
            // anything in the directory. 
            if (!canonicalPath.equals(WHITELISTED_PATH + "\\EmailAddresses.txt")) {
                return false;
            } else {
                return canonicalPath.contains(WHITELISTED_PATH);
            }
        } catch (IOException io) {
            System.out.println("Invalid File.");
        }
        return false;
    }

    // validates whehter line in file is in format of an email xxx@xxx.xxx
    // returns false and doesn't print line if invalid
    private static boolean validEmail(String email) {
        matcher = EMAIL_PATTERN.matcher(email);
        if (email == null) {

            return false;
        }
        // returns valid email patterns from pattern
        return matcher.matches();
    }
}
