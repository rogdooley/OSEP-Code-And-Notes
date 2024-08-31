using System;
using System.Data.SqlClient;
using System.IO;

class Program
{
    static void Main(string[] args)
    {
        // Define default connection details
        string server = null;
        string database = null;
        string[] queries = null;

        // Parse command-line arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-s":
                    if (i + 1 < args.Length)
                    {
                        server = args[++i];
                    }
                    break;
                case "-d":
                    if (i + 1 < args.Length)
                    {
                        database = args[++i];
                    }
                    break;
                case "-f":
                    if (i + 1 < args.Length)
                    {
                        string filePath = args[++i];
                        if (File.Exists(filePath))
                        {
                            queries = File.ReadAllLines(filePath);
                        }
                        else
                        {
                            Console.WriteLine("File not found: " + filePath);
                            return;
                        }
                    }
                    break;
            }
        }

        // Validate required arguments
        if (string.IsNullOrEmpty(server) || string.IsNullOrEmpty(database))
        {
            Console.WriteLine("Usage: Program -s <server> -d <database> [-f <query file>]");
            return;
        }

        // If no file is provided, use a default query
        if (queries == null)
        {
            queries = new string[]
            {
                "SELECT TOP 10 * FROM sys.tables",
                "SELECT COUNT(*) FROM sys.databases"
            };
        }

        // Build the connection string for Kerberos authentication
        string connectionString = $"Server={server};Database={database};Integrated Security=SSPI;";

        // Create a new SQL connection object
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            try
            {
                // Open the connection
                connection.Open();

                foreach (string query in queries)
                {
                    // Create a SQL command object for each query
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        // Execute the query and store results
                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            // Display the query results
                            Console.WriteLine($"Results for query: {query}");
                            while (reader.Read())
                            {
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    Console.WriteLine($"{reader.GetName(i)}: {reader.GetValue(i)}");
                                }
                                Console.WriteLine("-------------------");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }
    }
}
