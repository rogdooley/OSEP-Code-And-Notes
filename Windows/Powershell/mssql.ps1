# Define connection details
$server = "dc01.corp1.com"
$database = "master"

# Build the connection string for Kerberos authentication
$connectionString = "Server=$server;Database=$database;Integrated Security=SSPI;"

# Create a new SQL connection object
$connection = New-Object System.Data.SqlClient.SqlConnection
$connection.ConnectionString = $connectionString

try {
    # Open the connection
    $connection.Open()

    # List of queries to execute
    $queries = @(
        "SELECT SYSTEM_USER;",
        "SELECT IS_SRVROLEMEMBER('public');",
        "SELECT name FROM sys.tables"
    )

    foreach ($query in $queries) {
        # Create a SQL command object for each query
        $command = $connection.CreateCommand()
        $command.CommandText = $query

        # Execute the query and store results
        $reader = $command.ExecuteReader()

        # Display the query results
        Write-Host "Results for query: $query"
        while ($reader.Read()) {
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                Write-Host "$($reader.GetName($i)): $($reader.GetValue($i))"
            }
            Write-Host "-------------------"
        }

        # Close the reader after each query
        $reader.Close()
    }
}
catch {
    Write-Host "An error occurred: $_"
}
finally {
    # Ensure the connection is closed even if an error occurs
    $connection.Close()
}
