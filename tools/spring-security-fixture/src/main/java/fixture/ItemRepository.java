package fixture;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.stereotype.Repository;

/** 일회용 H2 메모리 DB만 사용한다. 외부 DB 설정이나 파일 DB를 받지 않는다. */
@Repository
public class ItemRepository implements AutoCloseable {
    private final Connection db;

    public ItemRepository() throws SQLException {
        db = DriverManager.getConnection("jdbc:h2:mem:localcode_fixture;DB_CLOSE_DELAY=-1");
        try (var statement = db.createStatement()) {
            statement.execute("CREATE TABLE items (id VARCHAR(80) PRIMARY KEY, owner_name VARCHAR(80) NOT NULL)");
        }
    }

    public synchronized void put(String id, String owner) throws SQLException {
        try (PreparedStatement statement = db.prepareStatement("MERGE INTO items (id, owner_name) KEY(id) VALUES (?, ?)")) {
            statement.setString(1, id);
            statement.setString(2, owner);
            statement.executeUpdate();
        }
    }

    public synchronized String owner(String id) throws SQLException {
        try (PreparedStatement statement = db.prepareStatement("SELECT owner_name FROM items WHERE id = ?")) {
            statement.setString(1, id);
            try (ResultSet rows = statement.executeQuery()) {
                return rows.next() ? rows.getString(1) : null;
            }
        }
    }

    public synchronized void delete(String id) throws SQLException {
        try (PreparedStatement statement = db.prepareStatement("DELETE FROM items WHERE id = ?")) {
            statement.setString(1, id);
            statement.executeUpdate();
        }
    }

    @Override public void close() throws SQLException { db.close(); }
}
