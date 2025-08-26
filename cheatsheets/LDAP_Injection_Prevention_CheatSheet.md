// ❌ Insecure example (Do NOT use - vulnerable to LDAP Injection)
String filter = "(&(uid=" + userInput + ")(objectClass=person))";
NamingEnumeration<SearchResult> results = ctx.search(
    "ou=users,dc=example,dc=com",
    filter,
    controls
);

// ✅ Secure example (Use parameterized filter with placeholders)
String filter = "(&(uid={0})(objectClass=person))";
Object[] filterArgs = new Object[] { userInput };

NamingEnumeration<SearchResult> results = ctx.search(
    "ou=users,dc=example,dc=com",
    filter,
    filterArgs,
    controls
);

