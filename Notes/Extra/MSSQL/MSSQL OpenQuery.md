
Executing stored procedures on a linked SQL Server can be accomplished using the `OPENQUERY` function in T-SQL. This method allows you to run a pass-through query on the linked server, enabling you to execute commands as if you were connected directly to that server.

In this guide, we'll explore how to use `OPENQUERY` to execute stored procedures on a linked server, discuss alternative methods, and provide examples to illustrate each approach.

---

## **Table of Contents**

1. [Understanding OPENQUERY](#understanding-openquery)
2. [Prerequisites](#prerequisites)
3. [Basic Syntax of OPENQUERY](#basic-syntax-of-openquery)
4. [Executing Stored Procedures using OPENQUERY](#executing-stored-procedures-using-openquery)
    - [Example 1: Executing a Stored Procedure without Parameters](#example-1-executing-a-stored-procedure-without-parameters)
    - [Example 2: Executing a Stored Procedure with Parameters](#example-2-executing-a-stored-procedure-with-parameters)
5. [Using EXECUTE AT as an Alternative](#using-execute-at-as-an-alternative)
    - [Example 3: EXECUTE AT without Parameters](#example-3-execute-at-without-parameters)
    - [Example 4: EXECUTE AT with Parameters](#example-4-execute-at-with-parameters)
6. [Handling Output Parameters and Return Values](#handling-output-parameters-and-return-values)
7. [Performance Considerations](#performance-considerations)
8. [Security Considerations](#security-considerations)
9. [Conclusion](#conclusion)
10. [References](#references)

---

## **Understanding OPENQUERY**

`OPENQUERY` is a function in SQL Server that executes a pass-through query on a linked server. The query is sent directly to the linked server for processing, and the results are returned to the local server.

**Key Characteristics:**

- **Pass-Through Execution**: The query is executed entirely on the linked server.
- **Read-Only**: Generally used for SELECT statements, but can execute stored procedures that perform data modification.
- **Static Query**: The query string must be a constant and cannot be built dynamically within the `OPENQUERY` statement.

**Use Cases:**

- Querying data from remote servers.
- Executing complex queries that are better processed on the remote server.
- Running stored procedures on linked servers.

---

## **Prerequisites**

Before using `OPENQUERY` to execute stored procedures, ensure the following:

1. **Linked Server Configuration**: The remote server must be configured as a linked server on your local SQL Server instance.

2. **Appropriate Permissions**: You must have the necessary permissions to execute queries and stored procedures on the linked server.

3. **Network Connectivity**: Ensure that the local server can communicate with the linked server over the network.

**Creating a Linked Server Example:**

```sql
EXEC sp_addlinkedserver 
    @server = 'LinkedServerName', 
    @srvproduct = '', 
    @provider = 'SQLNCLI', 
    @datasrc = 'RemoteServerName';

EXEC sp_addlinkedsrvlogin 
    @rmtsrvname = 'LinkedServerName', 
    @useself = 'false', 
    @rmtuser = 'username', 
    @rmtpassword = 'password';
```

---

## **Basic Syntax of OPENQUERY**

The basic syntax of `OPENQUERY` is as follows:

```sql
SELECT * FROM OPENQUERY (linked_server ,'query');
```

**Parameters:**

- `linked_server`: The name of the linked server as defined in your SQL Server instance.
- `'query'`: The query string to execute on the linked server. This must be a constant string.

**Example:**

```sql
SELECT * FROM OPENQUERY (LinkedServerName, 'SELECT * FROM DatabaseName.Schema.TableName');
```

---

## **Executing Stored Procedures using OPENQUERY**

You can execute stored procedures on a linked server using `OPENQUERY` by passing the appropriate EXEC command as the query string.

### **Example 1: Executing a Stored Procedure without Parameters**

**Stored Procedure on Linked Server:**

```sql
-- Assume this stored procedure exists on the linked server
CREATE PROCEDURE dbo.GetEmployees
AS
BEGIN
    SELECT EmployeeID, FirstName, LastName FROM HR.Employees;
END
```

**Executing via OPENQUERY:**

```sql
SELECT * FROM OPENQUERY (
    LinkedServerName, 
    'EXEC DatabaseName.dbo.GetEmployees'
);
```

**Explanation:**

- The `EXEC` command is passed as a string to `OPENQUERY`.
- The result set returned by the stored procedure is returned to the local server.
- Ensure that the database and schema names are correctly specified.

### **Example 2: Executing a Stored Procedure with Parameters**

**Stored Procedure on Linked Server:**

```sql
CREATE PROCEDURE dbo.GetEmployeeByID
    @EmployeeID INT
AS
BEGIN
    SELECT EmployeeID, FirstName, LastName FROM HR.Employees WHERE EmployeeID = @EmployeeID;
END
```

**Executing via OPENQUERY:**

Since `OPENQUERY` does not support parameterization directly, you must construct the query string with the parameters embedded.

**Using Concatenation:**

```sql
DECLARE @EmployeeID INT = 5;
DECLARE @qry NVARCHAR(1000);

SET @qry = 'SELECT * FROM OPENQUERY (
    LinkedServerName, 
    ''EXEC DatabaseName.dbo.GetEmployeeByID ' + CAST(@EmployeeID AS VARCHAR(10)) + '''
)';

EXEC (@qry);
```

**Explanation:**

- The query string is constructed by concatenating the parameter value.
- Double single quotes (`''`) are used to escape single quotes within the string.
- `EXEC` is used to execute the dynamically constructed query.

**Caution:** Be careful with this method to avoid SQL injection vulnerabilities. Ensure that parameter values are validated and sanitized.

**Alternative Using FORMATMESSAGE:**

```sql
DECLARE @EmployeeID INT = 5;
DECLARE @qry NVARCHAR(1000);

SET @qry = FORMATMESSAGE('SELECT * FROM OPENQUERY (LinkedServerName, ''EXEC DatabaseName.dbo.GetEmployeeByID %d'')', @EmployeeID);

EXEC (@qry);
```

**Explanation:**

- `FORMATMESSAGE` is used to safely format the string with parameters.
- It handles proper conversion and escaping of parameters.

---

## **Using EXECUTE AT as an Alternative**

`EXECUTE AT` is another method to execute commands on a linked server. It allows for parameterized queries and can be more flexible than `OPENQUERY`.

### **Example 3: EXECUTE AT without Parameters**

**Executing Stored Procedure:**

```sql
EXECUTE ('EXEC DatabaseName.dbo.GetEmployees') AT LinkedServerName;
```

**Explanation:**

- The command within the parentheses is executed on the specified linked server.
- Simple and straightforward for executing stored procedures without parameters.

### **Example 4: EXECUTE AT with Parameters**

**Executing Stored Procedure with Parameters:**

```sql
DECLARE @EmployeeID INT = 5;

EXECUTE AT LinkedServerName
    dbo.GetEmployeeByID
    @EmployeeID = @EmployeeID;
```

**Explanation:**

- Parameters can be passed directly, which is safer and cleaner.
- The remote procedure is specified along with its parameters.

**Using EXECUTE with String and Parameters:**

```sql
DECLARE @EmployeeID INT = 5;

EXECUTE (
    N'EXEC DatabaseName.dbo.GetEmployeeByID @EmployeeID'
) AT LinkedServerName
    PARAMS
    @EmployeeID INT = @EmployeeID;
```

**Explanation:**

- The `PARAMS` keyword allows specifying parameter types and values.
- Provides better control and safety over parameterized execution.

---

## **Handling Output Parameters and Return Values**

When dealing with output parameters and return values, additional handling is required.

**Example: Stored Procedure with Output Parameter:**

```sql
CREATE PROCEDURE dbo.GetEmployeeCount
    @DepartmentID INT,
    @EmployeeCount INT OUTPUT
AS
BEGIN
    SELECT @EmployeeCount = COUNT(*) FROM HR.Employees WHERE DepartmentID = @DepartmentID;
END
```

**Executing via EXECUTE AT with Output Parameter:**

```sql
DECLARE @DepartmentID INT = 2;
DECLARE @EmployeeCount INT;

EXECUTE AT LinkedServerName
    dbo.GetEmployeeCount
    @DepartmentID = @DepartmentID,
    @EmployeeCount = @EmployeeCount OUTPUT;

SELECT @EmployeeCount AS EmployeeCount;
```

**Explanation:**

- Output parameters are specified with the `OUTPUT` keyword.
- The local variable `@EmployeeCount` receives the value from the remote execution.
- This method allows seamless retrieval of output parameters.

---

## **Performance Considerations**

- **Network Latency**: Executing queries over the network can introduce latency. Ensure network reliability and speed.
- **Data Volume**: Transferring large result sets can be slow. Consider filtering data as much as possible on the remote server.
- **Query Optimization**: Ensure that the stored procedures are optimized for performance on the remote server.
- **Connection Overhead**: Frequent connections to the linked server can introduce overhead. Reuse connections where possible.

---

## **Security Considerations**

- **Permissions**: Ensure that the executing account has appropriate permissions on both local and linked servers.
- **Credential Management**: Use secure methods for storing and transmitting credentials.
- **SQL Injection**: When constructing dynamic queries, validate and sanitize all inputs to prevent SQL injection attacks.
- **Encryption**: Consider using encrypted connections between servers for sensitive data.
- **Audit and Logging**: Monitor and log remote executions for auditing and troubleshooting purposes.

---

## **Conclusion**

Using `OPENQUERY` and `EXECUTE AT` allows you to execute stored procedures on linked SQL Servers effectively. Choose the method that best suits your needs:

- **OPENQUERY** is suitable for executing queries and procedures where dynamic SQL is acceptable, but parameterization is limited.
- **EXECUTE AT** offers better support for parameterized execution and handling of output parameters.

Always consider performance and security implications when executing remote procedures, and ensure proper error handling and logging are in place.

---

## **References**

- [Microsoft Docs: OPENQUERY](https://docs.microsoft.com/en-us/sql/t-sql/functions/openquery-transact-sql)
- [Microsoft Docs: EXECUTE (Transact-SQL)](https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql)
- [Microsoft Docs: sp_addlinkedserver (Transact-SQL)](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addlinkedserver-transact-sql)
- [SQL Server Linked Servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine)

---

In SQL Server, you can use the `OPENQUERY` keyword to execute queries on a linked server, including executing stored procedures. `OPENQUERY` is used to run a pass-through query on the linked server, meaning that the entire query is sent to the remote server and executed there, rather than locally on the source server.

Here’s how you can execute a stored procedure on a linked SQL Server using `OPENQUERY`.

### **Syntax of `OPENQUERY`**

```sql
SELECT * 
FROM OPENQUERY([LinkedServerName], 'EXEC DatabaseName.Schema.StoredProcedureName Parameters');
```

### **Example 1: Executing a Stored Procedure Without Parameters**

Assume you have a linked server called `LinkedServer1` and a stored procedure `spGetCustomers` in the database `AdventureWorks`.

```sql
SELECT * 
FROM OPENQUERY([LinkedServer1], 'EXEC AdventureWorks.dbo.spGetCustomers');
```

- **`LinkedServer1`**: The name of the linked server.
- **`AdventureWorks.dbo.spGetCustomers`**: The stored procedure to execute on the linked server.

### **Example 2: Executing a Stored Procedure With Parameters**

If the stored procedure takes parameters, you can include them in the `OPENQUERY` statement as part of the pass-through query.

#### Stored Procedure Example:

```sql
CREATE PROCEDURE dbo.spGetOrdersByCustomer
    @CustomerID INT
AS
BEGIN
    SELECT * FROM Orders WHERE CustomerID = @CustomerID;
END;
```

To call this stored procedure on a linked server and pass a parameter (`@CustomerID = 5`):

```sql
SELECT * 
FROM OPENQUERY([LinkedServer1], 'EXEC AdventureWorks.dbo.spGetOrdersByCustomer 5');
```

In this example:
- The linked server is `LinkedServer1`.
- The stored procedure `spGetOrdersByCustomer` in the `AdventureWorks` database is executed with the parameter `5`.

### **Limitations of `OPENQUERY`**
1. **Result Set**: `OPENQUERY` can only return a result set (i.e., results from a `SELECT` query). If the stored procedure does not return a result set (e.g., it only modifies data), you may need to adjust your query.
   
2. **Dynamic Execution**: `OPENQUERY` requires the query to be a constant string. If you need to build the query dynamically (e.g., to pass dynamic parameters), you will need to use `EXEC` with `sp_executesql` or similar methods.

### **Using `OPENQUERY` with Dynamic SQL**
Since `OPENQUERY` does not support dynamic SQL directly, you can build the query dynamically and execute it using `EXEC`:

```sql
DECLARE @query NVARCHAR(MAX)

SET @query = 'SELECT * FROM OPENQUERY([LinkedServer1], ''EXEC AdventureWorks.dbo.spGetOrdersByCustomer 5'')';

EXEC sp_executesql @query;
```

### **Example 3: Executing a Stored Procedure That Does Not Return a Result Set**

If the stored procedure modifies data (e.g., `INSERT`, `UPDATE`, or `DELETE`) and does not return a result set, you can use `OPENQUERY` just to execute the procedure without selecting anything.

```sql
EXEC OPENQUERY([LinkedServer1], 'EXEC AdventureWorks.dbo.spUpdateCustomerInfo 1, ''NewName''');
```

In this case, the stored procedure `spUpdateCustomerInfo` is executed on the linked server, and no result set is returned.

### **Best Practices**

1. **Permissions**: Ensure that the SQL Server login or user on the local server has the appropriate permissions to execute queries on the linked server.
   
2. **Performance**: Since `OPENQUERY` runs the query on the remote server, it’s important to monitor network performance and ensure that the query is optimized to minimize data transfer between the linked and local servers.

3. **Handling Errors**: If the stored procedure on the linked server fails or raises an error, it will be reported back to the local server. Consider handling errors with `TRY...CATCH` blocks.


You can combine `OPENQUERY` and a stored procedure in SQL Server to execute PowerShell commands on a linked SQL Server by leveraging SQL Server's ability to execute operating system commands via `xp_cmdshell`. However, doing this requires careful consideration of security implications.

Here’s how you can create a stored procedure that uses `OPENQUERY` to execute a PowerShell command on a linked SQL Server.

### **Step 1: Enable `xp_cmdshell` on the Linked Server**
Before you can execute PowerShell commands, you need to ensure that `xp_cmdshell` is enabled on the linked SQL Server. This is necessary because `xp_cmdshell` is what allows SQL Server to execute operating system commands like PowerShell.

#### On the linked server:
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

### **Step 2: Create the Stored Procedure on the Local Server**
You will create a stored procedure on your local server that uses `OPENQUERY` to run a PowerShell command via `xp_cmdshell` on the linked server.

#### Example Stored Procedure
```sql
CREATE PROCEDURE [dbo].[ExecutePowerShellOnLinkedServer]
    @LinkedServerName NVARCHAR(128),
    @PowerShellCommand NVARCHAR(MAX)
AS
BEGIN
    DECLARE @SQL NVARCHAR(MAX);
    
    -- Construct the query to be executed on the linked server
    SET @SQL = 'SELECT * FROM OPENQUERY([' + @LinkedServerName + '], ''EXEC master..xp_cmdshell "powershell.exe -Command ' + @PowerShellCommand + '" '')';

    -- Execute the constructed query
    EXEC sp_executesql @SQL;
END;
```

### **Explanation:**
- **`@LinkedServerName`**: The name of the linked server where you want to execute the PowerShell command.
- **`@PowerShellCommand`**: The PowerShell command to be executed on the linked server.
- **`@SQL`**: This is the dynamic SQL query that will be executed on the linked server via `OPENQUERY`.

### **Step 3: Execute the Stored Procedure**
You can now execute the stored procedure and pass in the name of the linked server along with the PowerShell command you want to run.

#### Example Usage:
```sql
EXEC [dbo].[ExecutePowerShellOnLinkedServer] 
    @LinkedServerName = 'LinkedServer1', 
    @PowerShellCommand = 'Get-Process';
```

This example executes the `Get-Process` PowerShell command on the linked server `LinkedServer1`.

### **Security Considerations:**
- **Permissions**: Ensure that the account executing this stored procedure has the appropriate permissions to run `xp_cmdshell` on the linked server.
- **Security Risks**: Executing PowerShell commands via `xp_cmdshell` can be risky and may expose the server to potential security threats. It’s crucial to ensure that this capability is strictly controlled and only used when necessary.
- **Audit and Monitoring**: Consider auditing and monitoring the use of this stored procedure to prevent unauthorized or malicious use.

