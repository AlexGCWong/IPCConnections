/ open and save the port numer to file portnumber.txt
\p 0W
`:portnumber.txt set system "p";

/ check to see if file exists
if[() ~ key `:/passwordDir/passtable ;
	`:passwordDir/passtable set 
	([user:`$()] salt:();password:())]
if[() ~ key `:logfiles/auth.log ;
	`:logfiles/auth.log set 
	([]time:`timestamp$();user:`$();allowed:`boolean$())]
if[() ~ key `:logfiles/connection.log ;
	`:logfiles/connection.log set 
	([]time:`timestamp$();user:`$();handle:`int$();connection:())]
if[() ~ key `:logfiles/query.log ;
	`:logfiles/query.log set 
	([]time:`timestamp$();user:`$();query:();queryType:())]

/ loads all the log files	
system "l passwordDir/passtable"
system "l logfiles/auth.log"
system "l logfiles/connection.log"
system "l logfiles/query.log"


/ define functions for the password tables
.hashtable.toString:{[convert] $[10h=abs type convert;convert;string convert]}

.hashtable.encrypt:{[pwd;randomSalt] md5 (string randomSalt), .hashtable.toString pwd}
.hashtable.salting:{system "./salting.sh"; `$ raze read0 `:salt.txt}
.hashtable.addToTable:{[u;pwd] randomSalt:.hashtable.salting[];
	`:passwordDir/passtable upsert enlist(u;randomSalt;.hashtable.encrypt[pwd;randomSalt]);
	system "l passwordDir/passtable" 
  }
.hashtable.add:{[users;pwd]
	$[users in key passtable;0N!"username exists";(.hashtable.addToTable[users;pwd])]}
	

/ some examples	to populate the password table with
.hashtable.add[`fakeuser1;`pass1];
.hashtable.add[`fakeuser2;`pass2];
.hashtable.add[`fakeuser3;`pass3];
.hashtable.add[`caspar;`pass4];
.hashtable.add[`alex;`notapassword];
.hashtable.add[`caspar2;`pass5];
.hashtable.add[`alex2;`notapassword2];

/ method to update the password in the password table
.hashtable.updatepass:{[users;oldpass;newpass]
		accepted:$[.hashtable.encrypt[oldpass;passtable[users][`salt]]~passtable[users][`password];
		.hashtable.changePassword[users;newpass];
		0N!"incorrect password"]}

/ method to change the password in the password table file
.hashtable.changePassword:{[users;pwd]	
	delete from `passtable where user=users;
	.hashtable.addToTable[users;pwd]}

/ method to delete a user
.hashtable.deleteUser:{[users;pwd]
	$[.hashtable.encrypt[pwd;passtable[users][`salt]]~passtable[users][`password];
	delete from `passtable where user=users;
	0N!"incorrect password"];
	`:passwordDirpasstable set passtable}

/ defines the .z.pw method which is run everytime a user logs in
.z.pw:{[user;pwd]
	accepted:$[.hashtable.encrypt
		[pwd;passtable[user][`salt]]~passtable[user][`password];1b;0b];
	0N! (.z.P;"Connection request(",string[.z.w],") from:",string[user]);
	`:logfiles/auth.log upsert enlist (.z.p;user;accepted);accepted
 }
 
/ runs everytime a connection is opened
.z.po:{[handle]
	0N!(.z.P;".z.po Connection:",
	string [.z.w]," opened by ",
	string .z.u)
 }

/ logs all connections opened
.z.po:{[oldzpo; handle]
	(oldzpo[handle]);
	`:logfiles/connection.log upsert enlist(.z.P ;.z.u;handle;"Open");
 }.z.po 

 
/ accepts all asynchronous queries
.z.ps:{[query]
	0N!(`.z.ps;.z.P;`handle`typ`query!
	(.z.w;`async;query));
 value query}
 
/ logs all asynchronous queries
.z.ps:{[oldzps; query]
	(oldzps[query]);
	`:logfiles/query.log upsert enlist (.z.P ;.z.u;query;"async");
 }.z.ps

/ accepts all synchronous queries
.z.pg:{[query]0N!
	(`.z.pg;.z.P;
	"Handle:",string[.z.w]," Synchronous query:",-3!query);
 value query}
 
/ logs all synchronous queries
.z.pg:{[oldzpg; query]
	(oldzpg[query]);
	`:logfiles/query.log upsert enlist (.z.P;.z.u ;query;"sync");
 }.z.pg 
 
/ runs everytime a connection is closed
.z.pc:{[oldhandle]0N!(`.z.pc;.z.P;
	"Connection closed for handle:",string oldhandle);
	-1""}
 
/ logs all connections closed
.z.pc:{[oldzpc; handle]
	(oldzpc[handle]);
	`:logfiles/connection.log upsert enlist (.z.P ;.z.u;handle;"Close");
 }.z.pc 
 
 