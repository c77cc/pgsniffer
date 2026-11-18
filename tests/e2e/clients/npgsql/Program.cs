using Npgsql;

if (args.Length != 1)
{
    throw new ArgumentException("expected PostgreSQL connection string");
}

await using var connection = new NpgsqlConnection(args[0]);
await connection.OpenAsync();
await using var command = new NpgsqlCommand("SELECT $1::text AS npgsql_value", connection);
command.Parameters.Add(new NpgsqlParameter<string> { TypedValue = "npgsql-client" });
var value = (string?)await command.ExecuteScalarAsync();
if (value != "npgsql-client")
{
    throw new InvalidOperationException($"unexpected Npgsql query result: {value}");
}
