---
title: Query Parameterization Cheat Sheet
permalink: /Query_Parameterization_Cheat_Sheet/
---

`__NOTOC__`

<div style="width:100%;height:160px;border:0,margin:0;overflow: hidden;">
[link=](/File:Cheatsheets-header.jpg\ "wikilink")

</div>
{\\| style="padding: 0;margin:0;margin-top:10px;text-align:left;" \\|- \\| valign="top" style="border-right: 1px dotted gray;padding-right:25px;" \\| Last revision (mm/dd/yy): **//**

Introduction
============

`__TOC__`

[SQL Injection](/SQL_Injection "wikilink") is one of the most dangerous web vulnerabilities. So much so that it's the [\#1 item in the OWASP Top 10](/Top_10_2013-A1\ "wikilink"). It represents a serious threat because SQL Injection allows evil attacker code to change the structure of a web application's SQL statement in a way that can steal data, modify data, or potentially facilitate command injection to the underlying OS. This cheat sheet is a derivative work of the [SQL Injection Prevention Cheat Sheet](/SQL_Injection_Prevention_Cheat_Sheet "wikilink").

Parameterized Query Examples
============================

SQL Injection is best prevented through the use of [*parameterized queries*](/SQL_Injection_Prevention_Cheat_Sheet#Defense_Option_1:_Prepared_Statements_.28Parameterized_Queries.29\ "wikilink"). The following chart demonstrates, with real-world code samples, how to build parameterized queries in most of the common web languages. The purpose of these code samples is to demonstrate to the web developer how to avoid SQL Injection when building database queries within a web application.

Prepared Statement Examples
---------------------------

{\\| class="wikitable nowraplinks" \\|- ! Language - Library ! Parameterized Query \\|- \\| Java - Standard \\|

`String custname = request.getParameter("customerName"); `
`String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";  `
**`PreparedStatement` `pstmt` `=` `connection.prepareStatement(` `query` `);`**
`'''pstmt.setString( 1, custname); '''`
`ResultSet results = pstmt.executeQuery( );`

\\|- \\| Java - Hibernate \\|

`//HQL `
`@Entity // declare as entity;`
**`@NamedQuery(`**
` `**`name="findByDescription",`**
` `**`query="FROM` `Inventory` `i` `WHERE` `i.productDescription` `=` `:productDescription"`**
**`)`**
`public class Inventory implements Serializable {`
` @Id`
` private long id;`
` private String productDescription;`
`}`
` // use case `
`String userSuppliedParameter = request.getParameter("Product-Description"); // This should REALLY be validated too`
`// perform input validation to detect attacks`
**`List`<Inventory> `list` `=`**
` `**`session.getNamedQuery("findByDescription")`**
` `**`.setParameter("productDescription",` `userSuppliedParameter).list();`**

`//Criteria API`
`String userSuppliedParameter = request.getParameter("Product-Description"); // This should REALLY be validated too`
`// perform input validation to detect attacks`
`Inventory inv = (Inventory) session.createCriteria(Inventory.class).add`
`(Restrictions.eq("productDescription", userSuppliedParameter)).uniqueResult();`

\\|- \\| .NET/C\# \\|

`String query = "SELECT account_balance FROM user_data WHERE user_name = ?";`
`try {`
`   OleDbCommand command = new OleDbCommand(query, connection);`
`   `**`command.Parameters.Add(new` `OleDbParameter("customerName",` `CustomerName` `Name.Text));`**
`   OleDbDataReader reader = command.ExecuteReader();`
`   // …`
`} catch (OleDbException se) {`
`   // error handling`
`} `

\\|- \\| ASP.NET \\|

`string sql = "SELECT * FROM Customers WHERE CustomerId = @CustomerId";`
**`SqlCommand` `command` `=` `new` `SqlCommand(sql);`**
**`command.Parameters.Add(new` `SqlParameter("@CustomerId",` `System.Data.SqlDbType.Int));`**
`command.Parameters["@CustomerId"].Value = 1;`

\\|- \\| Ruby - ActiveRecord \\|

**`#` `Create`**
`Project.create!(:name => 'owasp')`
**`#` `Read`**
`Project.all(:conditions => "name = ?", name)`
`Project.all(:conditions => { :name => name })`
`Project.where("name = :name", :name => name)`
**`#` `Update`**
`project.update_attributes(:name => 'owasp')`
**`#` `Delete`**
`Project.delete(:name => 'name')`

\\|- \\| Ruby \\|

`insert_new_user = db.prepare "INSERT INTO users (name, age, gender) VALUES (?, ? ,?)"`
`insert_new_user.execute 'aizatto', '20', 'male'`

\\|- \\| PHP - PDO \\|

`$stmt = $dbh->prepare("INSERT INTO REGISTRY (name, value) VALUES (:name, :value)");`
**`$stmt->bindParam(':name',` `$name);`**
**`$stmt->bindParam(':value',` `$value);`**

\\|- \\| Cold Fusion \\|

<cfquery name = "getFirst" dataSource = "cfsnippets">
`    `**`SELECT` `*` `FROM` `#strDatabasePrefix#_courses` `WHERE` `intCourseID` `=`**
`    `**<cfqueryparam value = #intCourseID# CFSQLType = "CF_SQL_INTEGER">**
</cfquery>

\\|- \\| Perl - DBI \\|

`my $sql = "INSERT INTO foo (bar, baz) VALUES ( ?, ? )";`
**`my` `$sth` `=` `$dbh->prepare(` `$sql` `);`**
**`$sth->execute(` `$bar,` `$baz` `);`**

\\|}

Stored Procedure Examples
-------------------------

The SQL you write in your web application isn't the only place that SQL injection vulnerabilities can be introduced. If you are using Stored Procedures, and you are dynamically constructing SQL inside them, you can also introduce SQL injection vulnerabilities. To ensure this dynamic SQL is secure, you can parameterize this dynamic SQL too using bind variables. Here are some examples of using bind variables in stored procedures in different databases:

{\\| class="wikitable nowraplinks" \\|- ! Language - Library ! Parameterized Query \\|- \\| Oracle - PL/SQL \\| Normal Stored Procedure - no dynamic SQL being created. Parameters passed in to stored procedures are naturally bound to their location within the query without anything special being required.

` PROCEDURE SafeGetBalanceQuery(`
`   UserID varchar, Dept varchar) AS BEGIN`
` `
`   SELECT balance FROM accounts_table WHERE user_ID = UserID AND department = Dept;`
` END;`

\\|- \\| Oracle - PL/SQL \\| Stored Procedure Using Bind Variables in SQL Run with EXECUTE. Bind variables are used to tell the database that the inputs to this dynamic SQL are 'data' and not possibly code.

` PROCEDURE AnotherSafeGetBalanceQuery(`
`   UserID varchar, Dept varchar) AS `
`   stmt VARCHAR(400); result NUMBER;`
` `
` BEGIN`
`   stmt := 'SELECT balance FROM accounts_table WHERE user_ID = :1`
`     AND department = :2';`
`   EXECUTE IMMEDIATE stmt INTO result USING UserID, Dept;`
`   RETURN result;`
` END;`

\\|- \\| SQL Server- Transact-SQL \\| Normal Stored Procedure - no dynamic SQL being created. Parameters passed in to stored procedures are naturally bound to their location within the query without anything special being required.

` PROCEDURE SafeGetBalanceQuery(`
`   @UserID varchar(20),`
`   @Dept varchar(10)) AS BEGIN`
` `
`   SELECT balance FROM accounts_table WHERE user_ID = @UserID AND department = @Dept`
` END`

\\|- \\| SQL Server- Transact-SQL \\| Stored Procedure Using Bind Variables in SQL Run with EXEC. Bind variables are used to tell the database that the inputs to this dynamic SQL are 'data' and not possibly code.

` PROCEDURE SafeGetBalanceQuery(@UserID varchar(20),`
`     @Dept varchar(10)) AS BEGIN`
`   DECLARE @sql VARCHAR(200)`
`   SELECT @sql = 'SELECT balance FROM accounts_table WHERE '`
`     + 'user_ID = @UID AND department = @DPT'`
`   EXEC sp_executesql @sql, `
`     '@UID VARCHAR(20), @DPT VARCHAR(10)',`
`     @UID=@UserID, @DPT=@Dept`
` END`

\\|}

References
==========

-   [The Bobby Tables site (inspired by the XKCD webcomic) has numerous examples in different languages of parameterized Prepared Statements and Stored Procedures](http://bobby-tables.com/)
-   OWASP [SQL Injection Prevention Cheat Sheet](/SQL_Injection_Prevention_Cheat_Sheet "wikilink")

Authors and Primary Editors
===========================

Jim Manico - jim \[at\] owasp.org
[Dave Wichers - dave.wichers](/User:Wichers\ "wikilink") \[at\] owasp.org
Neil Matatal - neil \[at\] owasp.org

Other Cheatsheets
=================

\\|}

[Category:Cheatsheets](/Category:Cheatsheets "wikilink")