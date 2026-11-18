package io.github.c77cc.pgsniffer;

import java.sql.DriverManager;

public final class JdbcClient {
    private JdbcClient() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("expected JDBC URL");
        }
        try (var connection = DriverManager.getConnection(args[0], "postgres", "");
             var statement = connection.prepareStatement("SELECT ?::text AS jdbc_value")) {
            statement.setString(1, "jdbc-client");
            try (var result = statement.executeQuery()) {
                if (!result.next() || !"jdbc-client".equals(result.getString(1)) || result.next()) {
                    throw new IllegalStateException("unexpected JDBC query result");
                }
            }
        }
    }
}
