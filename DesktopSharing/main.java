import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class VulnerableService {

    // Lỗi 1: Hardcoded Credentials (Mật khẩu nhúng trực tiếp trong mã nguồn)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "SuperSecretPassword123!";

    /**
     * Lỗi 2: SQL Injection
     * Truyền trực tiếp dữ liệu từ người dùng vào câu lệnh SQL thông qua nối chuỗi.
     */
    public void getUserByUsername(String username) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            // SonarQube rule: java:S2077 (SQL queries should not be vulnerable to injection attacks)
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                System.out.println("User found: " + rs.getString("username"));
            }
            
            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Lỗi 3: Path Traversal (Truy cập tệp tùy ý)
     * Không kiểm tra ký tự điều hướng thư mục (ví dụ: ../) trong tên file đầu vào.
     */
    public byte[] readFile(String fileName) throws IOException {
        // SonarQube rule: java:S5145 (Server-Side Request Forgery or Path Traversal)
        File file = new File("/var/www/uploads/" + fileName);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
    }

    /**
     * Lỗi 4: Weak Cryptography (Sử dụng thuật toán băm yếu - MD5)
     * MD5 không còn an toàn cho việc mã hóa mật khẩu hoặc dữ liệu nhạy cảm.
     */
    public String hashPassword(String password) {
        try {
            // SonarQube rule: java:S2070 (The use of weak cryptographic hash algorithms should be avoided)
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}