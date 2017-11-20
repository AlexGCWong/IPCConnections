/ finds the port number that the server is open on
port:get `:portnumber.txt
/ Assigns the handle to null
handle:0N

/ USAGE: login[`username;`password]
login:{[username;password]port:get `:portnumber.txt;
	handle::hopen`$(raze"::",string port,":",username,":",password);
	password:()
 }
	
/ USEAGE: execute "sample query here"
/ USEAGE: execute "0N! `helloServer"
/ USEAGE: execute "0N! \"Hello Server\""
execute:{[codeToExecute]$[null handle;
	0N!"you are not logged in";
	handle codeToExecute]}
	
/ a simple method to delete a user
/ TODO: provide a method such that the client can only delete themselves from the password file
/ USEAGE: deleteUser[`username;`password]
deleteUser:{[username;password]$[null handle;
	"you are not logged in";
	execute[raze raze ".hashtable.deleteUser[`",string username,";`",string password, "]"]];
	logout[]}

/ logout
/ USEAGE: logout[]
logout:{if[not null handle; hclose handle];handle::0N}
