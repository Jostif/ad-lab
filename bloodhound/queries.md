# BloodHound Custom Queries — J0stif

Custom Cypher queries for BloodHound CE / legacy.
Import `custom-queries.json` directly into the BloodHound UI,
or run queries manually in the raw query box.

---

## How to import

**BloodHound CE:**
1. Open BloodHound UI
2. Go to **Explore** → **Cypher** tab
3. Click **Manage Queries** → **Import**
4. Select `custom-queries.json`

**Legacy BloodHound:**
Copy contents of `custom-queries.json` into:
`~/.config/bloodhound/customqueries.json`

---

## Query index

### Kerberoasting
- Find all Kerberoastable users
- Kerberoastable users with DA path
- Kerberoastable users in high-value groups

### AS-REP Roasting
- Find accounts with pre-auth disabled

### Shadow Credentials
- Find users with GenericWrite (shadow creds targets)
- Find computers with GenericWrite

### ADCS
- Find ESC1 vulnerable templates
- Find ESC4 vulnerable templates (WriteOwner on template)
- Find users who can enroll in any template

### RBCD
- Find computers with GenericWrite (RBCD targets)
- Find RBCD paths to Domain Controllers

### RODC / KeyList
- Find accounts in Allowed RODC Password Replication Group
- Find accounts NOT in Denied RODC Password Replication Group

### Shortest paths
- Shortest path to Domain Admins from owned nodes
- Shortest path to DA from a specific user
- All paths to high-value targets

### Misc
- Find users with DCSync rights
- Find AdminSDHolder members
- Find computers where DA has sessions
- Find cross-domain trust paths

---

## Raw queries

### Kerberoasting

```cypher
// All Kerberoastable users (enabled, not DA)
MATCH (u:User)
WHERE u.hasspn = true
AND u.enabled = true
AND NOT u.name STARTS WITH 'KRBTGT'
RETURN u.name, u.serviceprincipalnames
ORDER BY u.name

// Kerberoastable users with a path to DA
MATCH (u:User {hasspn:true, enabled:true})
MATCH p = shortestPath((u)-[*1..]->(g:Group {name:'DOMAIN ADMINS@LAB.LOCAL'}))
RETURN u.name, length(p) as hops
ORDER BY hops

// Kerberoastable accounts in privileged groups
MATCH (u:User {hasspn:true})-[:MemberOf*1..]->(g:Group)
WHERE g.highvalue = true
RETURN u.name, g.name
```

### AS-REP Roasting

```cypher
// Accounts with pre-auth disabled
MATCH (u:User {dontreqpreauth:true, enabled:true})
RETURN u.name, u.description
ORDER BY u.name
```

### Shadow Credentials / GenericWrite

```cypher
// Users with GenericWrite over other users (shadow creds targets)
MATCH (a)-[:GenericWrite]->(b:User)
WHERE a.enabled = true
RETURN a.name as attacker, b.name as target, labels(a) as attacker_type
ORDER BY b.name

// Computers with GenericWrite (RBCD + shadow creds)
MATCH (a)-[:GenericWrite]->(c:Computer)
WHERE a.enabled = true
RETURN a.name as attacker, c.name as target
ORDER BY c.name

// All write edges to high-value targets
MATCH (a)-[r:GenericWrite|GenericAll|WriteDacl|WriteOwner|Owns]->(b)
WHERE b.highvalue = true
AND a.enabled = true
RETURN a.name, type(r), b.name
ORDER BY b.name
```

### ADCS

```cypher
// ESC1: templates where low-priv users can enroll + supply SAN
MATCH (t:GPO)-[:HasTemplate]->(ct:CertTemplate)
WHERE ct.enrolleeSuppliesSubject = true
AND ct.requiresManagerApproval = false
AND ct.authenticationEnabled = true
RETURN ct.name, ct.displayname

// Users who can enroll in any certificate template
MATCH (u:User)-[:Enroll|AutoEnroll]->(ct:CertTemplate)
WHERE u.enabled = true
RETURN u.name, collect(ct.name) as templates
ORDER BY u.name

// ESC4: WriteOwner on a certificate template
MATCH (a)-[r:WriteOwner|Owns|WriteDacl|GenericAll]->(ct:CertTemplate)
WHERE a.enabled = true
RETURN a.name, type(r), ct.name
```

### RBCD

```cypher
// Computers where current owned user has GenericWrite (RBCD targets)
MATCH (a {owned:true})-[:GenericWrite]->(c:Computer)
RETURN a.name as owned, c.name as rbcd_target

// RBCD delegation paths to Domain Controllers
MATCH p = (a)-[:GenericWrite]->(c:Computer)-[:DCFor]->(d:Domain)
WHERE a.enabled = true
RETURN a.name, c.name, d.name

// AllowedToDelegate edges (constrained delegation)
MATCH (a)-[:AllowedToDelegate]->(c:Computer)
WHERE a.enabled = true
RETURN a.name, a.allowedtodelegate, c.name
```

### RODC / KeyList

```cypher
// Accounts in Allowed RODC Password Replication Group
MATCH (u)-[:MemberOf*1..]->(g:Group)
WHERE g.name CONTAINS 'ALLOWED RODC PASSWORD'
RETURN u.name, labels(u)

// High-value accounts NOT in Denied RODC PRP (KeyList targets)
MATCH (u:User {enabled:true})
WHERE u.highvalue = true
AND NOT (u)-[:MemberOf*1..]->(:Group {name:'DENIED RODC PASSWORD REPLICATION GROUP@LAB.LOCAL'})
RETURN u.name
ORDER BY u.name

// RODC computer accounts
MATCH (c:Computer {isrodc:true})
RETURN c.name, c.operatingsystem
```

### DCSync

```cypher
// Users with DCSync rights (GetChanges + GetChangesAll)
MATCH (u)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain)
WHERE u.enabled = true
RETURN u.name, labels(u)
ORDER BY u.name

// All principals with replication rights
MATCH (a)-[r:GetChanges|GetChangesAll|DCSync]->(d:Domain)
RETURN a.name, type(r), d.name
```

### Shortest paths

```cypher
// Shortest path from owned nodes to Domain Admins
MATCH (owned {owned:true}), (da:Group {name:'DOMAIN ADMINS@LAB.LOCAL'})
MATCH p = shortestPath((owned)-[*1..10]->(da))
WHERE owned <> da
RETURN p

// All edges from a specific compromised user
MATCH (u:User {name:'JDOE@LAB.LOCAL'})
MATCH p = (u)-[r*1..5]->(target)
WHERE target.highvalue = true
RETURN p

// Computers where DA users have sessions (lateral movement targets)
MATCH (da:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@LAB.LOCAL'})
MATCH (da)-[:HasSession]->(c:Computer)
RETURN da.name, c.name
ORDER BY c.name
```

### AdminSDHolder

```cypher
// Users protected by AdminSDHolder (adminCount=1)
MATCH (u:User {admincount:true, enabled:true})
RETURN u.name, u.description
ORDER BY u.name

// Groups with AdminSDHolder protection
MATCH (g:Group {admincount:true})
RETURN g.name, g.description
```

### Trust paths

```cypher
// Cross-domain trust relationships
MATCH p = (d1:Domain)-[r:TrustedBy|HasTrust]->(d2:Domain)
RETURN d1.name, type(r), d2.name

// SID history abuse paths
MATCH (u:User)-[:HasSIDHistory]->(g:Group)
WHERE g.highvalue = true
RETURN u.name, g.name
```
