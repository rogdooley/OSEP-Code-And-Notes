using System;
using System.Data.SqlClient;
using System.IO;

class SQLSecurityCheck
{
    static void Main(string[] args)
    {
        // Command-line argument variables
        string hostname = null;
        string database = "master";
        string username = null;
        string password = null;
        bool integratedSecurity = false;
        string outputFile = "SecurityCheckResults.txt";

        // Parse command-line arguments
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-h":
                    hostname = args[++i];
                    break;
                case "-d":
                    database = args[++i];
                    break;
                case "-u":
                    username = args[++i];
                    break;
                case "-p":
                    password = args[++i];
                    break;
                case "-i":
                    integratedSecurity = true;
                    break;
                case "-help":
                    PrintHelp();
                    return;
            }
        }

        // Check for required arguments
        if (hostname == null || (!integratedSecurity && (username == null || password == null)))
        {
            Console.WriteLine("Error: Missing required arguments.");
            PrintHelp();
            return;
        }


        // Build the connection string
        string connectionString = integratedSecurity
            ? $"Server={hostname};Database={database};Integrated Security=True;"
            : $"Server={hostname};Database={database};User Id={username};Password={password};";

        // SQL queries to execute
        string[] queries = new string[]
        {
            // Try executing as sa 
            "EXECUTE AS LOGIN = 'sa';",

            // Check for Databases with the Trustworthy Property Set
            "SELECT 'Trustworthy Property Set' AS [Check], name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1;",

            // Check if xp_cmdshell is Enabled
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell';",

            // Check for CLR Enabled
            "EXEC sp_configure 'clr enabled';",

            // Check for Databases with DB_CHAINING Enabled
            "SELECT 'DB Chaining Enabled' AS [Check], name, is_db_chaining_on FROM sys.databases WHERE is_db_chaining_on = 1;",

            // Check for OLE Automation Procedures Enabled
            "EXEC sp_configure 'Ole Automation Procedures';",

            // Check for Unrestricted SQLCLR Assemblies
            "SELECT 'Unrestricted SQLCLR Assemblies' AS [Check], name, permission_set_desc FROM sys.assemblies WHERE permission_set_desc IN ('UNSAFE_ACCESS', 'EXTERNAL_ACCESS');",

            // Check for Elevated Permissions on Logins
            "SELECT 'Elevated Permissions on Logins' AS [Check], name, type_desc, is_disabled FROM sys.server_principals WHERE is_disabled = 0 AND (type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN', 'WINDOWS_GROUP')) AND name NOT LIKE 'NT AUTHORITY%';",

            // Check for PUBLIC Role Permissions
            "SELECT 'Public Role Permissions' AS [Check], class_desc, permission_name FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public') AND permission_name NOT IN ('CONNECT');",

            // Check for Open Linked Servers
            "SELECT 'Open Linked Servers' AS [Check], name, is_linked FROM sys.servers WHERE is_linked = 1;",

            // Check for Open Firewall Rules Allowing External Connections
            "EXEC sp_helpserver;"
        };

        try
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();
                using (StreamWriter writer = new StreamWriter(outputFile, false))
                {
                    writer.WriteLine("SQL Server Security Check Results");

                    foreach (var query in queries)
                    {
                        writer.WriteLine($"\n\nExecuting Query: {query}");
                        using (SqlCommand command = new SqlCommand(query, connection))
                        {
                            using (SqlDataReader reader = command.ExecuteReader())
                            {
                                while (reader.Read())
                                {
                                    for (int i = 0; i < reader.FieldCount; i++)
                                    {
                                        writer.Write($"{reader.GetName(i)}: {reader.GetValue(i)}\t");
                                    }
                                    writer.WriteLine();
                                }
                            }
                        }
                    }
                }
                Console.WriteLine($"Security checks completed. Results saved to {outputFile}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
    }

    static void PrintHelp()
    {
        Console.WriteLine("Usage: SQLSecurityCheck.exe -h hostname [-d database] [-u username] [-p password] [-i] [-help]");
        Console.WriteLine("  -h   Hostname or IP address of the SQL Server");
        Console.WriteLine("  -d   Database name (default is 'master')");
        Console.WriteLine("  -u   Username for SQL Server authentication (required unless -i is used)");
        Console.WriteLine("  -p   Password for SQL Server authentication (required unless -i is used)");
        Console.WriteLine("  -i   Use Integrated Security (Windows Authentication)");
        Console.WriteLine("  -help  Display this help message");
    }

}
