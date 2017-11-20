port:get `:portnumber.txt
handle:0N

login:{[username;password]port:get `:portnumber.txt;
	handle::hopen`$(raze"::",string port,":",username,":",password);
	password:()
	}
	
	
execute:{[codeToExecute]$[null handle;
	0N!"you are not logged in";
	handle codeToExecute]}
	
deleteUser:{[username;password]$[null handle;
	"you are not logged in";
	execute[raze raze ".hashtable.deleteUser[`",string username,";`",string password, "]"]];
	logout[]}

	
logout:{if[not null handle; hclose handle];handle::0N}
