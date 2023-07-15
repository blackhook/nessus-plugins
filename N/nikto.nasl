#TRUSTED 7c71f0d760ce09c3b15ef1d2473a0904371cade353feb85f8e49b8148791f31baacbf9bd4679e485f1112168ba8a2c3fe5b16e61d55ae7e0cc080ce8719e0483bbe31b83c50fdba5d073078b7d86b4b72a2f64278138d9816f300d6124946aef9b0f49df3f52f9b5005a41bd8de8c89a316a3aa79e037b5bf7feb27a21207267e5361764d7f71b2c8465dde480800cf4d767ed3940ee6bb722b5258588cc93a6a7985157a4492c7921439730b2cf3a427df26a315f60a9b214abd86ffec49dcefea6860d674e1c23e75642fa50dd1965c72674ac63a0552001606770ed982ca1c6b4e054ffa3e7e2102c416df1cc69db3f451ab58484f22bf77c92309bc475bd85d61afa6cd4f156694bacabdf0ccefcfe79525da315a04d44549bb657b49c4e57860dcf82524c6df510162adbe0239d649ff13938ef6cbecc3de4b454530ed59d6f6d09d5b59fd495185c47b5354fafe3021ca30d6293632a64d662b38425adb269f129a70b05dac1c6c15a9d703b7aec83646c1f60266f398e4f76fb85e5ec8547738ee9c7bf38e04c53c183504b1be22fa70b8cae6863e0196257cf3549243f70cd55213330f4e603568bc466edb7aa0250db4d5eb477c2fc59b8f08673dd2d94150f291bd5dc6738bbf40e9b2384a4691bc249e080f890e1782b572535bfe62c2f171de0f60aed78490e71820a6c4a8b9da9610e11db36b3a5c12200ff68
#TRUST-RSA-SHA256 b1530919e62ffe4e599ca72aafd5d12e2954d53274fc65b8a67aec03785905db24b680e28cadfb9489db4f4b3ca69a96d5adf7f7ffe35397eb885a0384007a1b73fad6de2a5b3970989d16ff989c0aae4d771b053f5fa2d8421493b7db9ed992b8a038a9ac3660c102e64c3dada04a87f24cf776b0f6371fb05156e93fbe51b28842aeb9a89af48df5d6fce77dbc314dbc3abda59da16e18d24ec50ca1e68cb7f344e33bb77e774b03c94d28e482ebbccbbb5262ec084ccc4215bb9d3fab3a7a1fe1ea7ac340eb01a7b42c912e65741a561c3b06d1bb51fd4b6e3f95ea1a0496d96e17aaeabce190183dbe0465aaec0d62b70eb6326d1cf8833ffe186c6947694b8693e02c1812e585192a803ef9ca14e5276f704d43f8180e25abaee819e53210bd9166c5af868700e7c86a5fd20ce92e70f049dab8ee16b6bbb306774007fbc4569026918dd51217558d7eb0017d50ed80d1938b12c8c0e955713fd58f1e26fbd5c4558ce7e9b31307a753368cb3b8d93b863e469e0795065a4a114c452f74908fc3ee90832a3ede8a4ee401b9f8ad55327ebaea1f11ef28cfdcb0a4549e864ebc5dffb6374e19cbeda828f40f7c4f40ffc412dc7c2278a473f7d1c7e20a7e40f771ace7b23c75118785e8bdda947f2bf0ec8fdffe30c28115c504718e657a11abccad14d6ab8cf7156829cc40c38c570659f22368ea14c6aae702610cf562
#
# (C) Tenable Network Security, Inc.
#
#%NASL_MIN_LEVEL 70300

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(14260);
 script_version("1.36");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english: "Nikto (NASL wrapper)");
 script_summary(english: "Run Nikto2.");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin runs Nikto2." );
 script_set_attribute(attribute:"description", value:
"This plugin runs Nikto2, an open source (GPL) web server scanner used
to perform comprehensive tests for multiple issues, such as outdated
server versions, potentially dangerous files or programs, version
specific problems, various configuration items, etc.

See the section 'plugins options' to configure it.");
 script_set_attribute(attribute:"see_also", value:"https://cirt.net/nikto2" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "find_service1.nasl", "httpver.nasl", "logins.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 script_timeout(0);
 script_add_preference(name:"Enable Nikto", type:"checkbox", value:"no");
 script_add_preference(name:"Disable if server never replies 404", type:"checkbox", value:"yes");

 script_add_preference(name:"Root directory", type:"entry", value:"");
 script_add_preference(name:"Pause between tests (s)", type:"entry", value:"");
 script_add_preference(name:"Scan CGI directories",
                       type:"radio", value:"User supplied;All;None");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 1 Show redirects");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 2 Show cookies received");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 3 Show all 200/OK responses");
 script_add_preference(type: "checkbox", value: "no", name: "Display: 4 Show URLs which require authentication");
 script_add_preference(type: "checkbox", value: "no", name: "Display: V Verbose Output");

 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 1 Interesting File / Seen in logs");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 2 Misconfiguration / Default File");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 3 Information Disclosure");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 4 Injection (XSS/Script/HTML)");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 5 Remote File Retrieval - Inside Web Root");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 6 Denial of Service");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 7 Remote File Retrieval - Server Wide");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 8 Command Execution / Remote Shell");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 9 SQL Injection");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: 0 File Upload");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: a Authentication Bypass");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: b Software Identification");
 script_add_preference(type: "checkbox", value: "no", name: "Tuning: c Remote Source Inclusion");
 if ( NASL_LEVEL >= 3000 )
  script_add_preference(type: "checkbox", value: "no", name: "Tuning: x Reverse Tuning Options (i.e., include all except specified)");

 script_add_preference(type: "checkbox", value: "no", name: "Mutate: 1 Test all files with all root directories");
 script_add_preference(type: "checkbox", value: "no", name: "Mutate: 2 Guess for password file names");
 if ( NASL_LEVEL >= 3000 )
 {
  script_add_preference(type: "checkbox", value: "no", name: "Mutate: 3 Enumerate user names via Apache (/~user type requests)");
  script_add_preference(type: "checkbox", value: "no", name: "Mutate: 4 Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)");
 }

 exit(0);
}

if (NASL_LEVEL >= 6000) exit(0);

if ( ! defined_func("pread")) exit(0, "nikto.nasl cannot run: pread() is not defined.");
cmd = NULL;

if ( find_in_path("nikto.pl") ) cmd = "nikto.pl";
else if ( find_in_path("nikto") ) cmd = "nikto";

if ( ! cmd && description) {
	if ( NASL_LEVEL < 3000 ) exit(0);
	exit(0, "Nikto was not found in '$PATH'.");
}

#

function my_cgi_dirs()	# Copied from http_func.inc
{
 local_var	kb;
 kb = get_kb_list("/tmp/cgibin");
 if(isnull(kb)) kb = make_list("/cgi-bin", "/scripts", "");
 else kb = make_list(kb, "");
}

if (! COMMAND_LINE)
{
 p = script_get_preference("Enable Nikto");
 if ( "yes" >!< p ) exit(0, "Nikto is not enabled (per policy).");
}

if (! defined_func("pread"))
{
  set_kb_item(name: "/tmp/UnableToRun/14254", value: TRUE);
  display("Script #14254 (nikto_wrapper) cannot run\n");
  exit(0, "nikto.nasl cannot run: pread() is not defined.");
}

if (! cmd)
{
  display("Nikto was not found in $PATH\n");
  exit(0, "Nikto was not found in '$PATH'.");
}

user = get_kb_item("http/login");
pass = get_kb_item("http/password");
ids = get_kb_item("Settings/Whisker/NIDS");

port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0, "No open HTTP port.");

# Nikto may generate many false positives if the web server is broken
p = script_get_preference("Disable if server never replies 404");
if ("yes" >< p || "no" >!< p)
{
no404 = get_kb_item("www/no404/" + port);
  if ( no404 ) exit(0, "The web server on port "+port+" does not return 404 codes.");
  s = http_open_socket(port);
  if (! s) exit(1, "TCP connection to port "+port+" failed.");
  r = http_get(port: port, item: '/'+ rand()+'/'+rand()+'.cgi');
  send(socket: s, data: r);
  r = recv_line(socket: s, length: 512);
  http_close_socket(s);
  if (r =~ '^HTTP/[0-9.]+ +(200|40[13])')
   exit(1, "The web server on port "+port+" does not return 404 code on random pages.");
}

i = 0;
argv[i++] = cmd;

p = script_get_preference("Scan CGI directories");
if (p)
if ("User supplied" >!< p)
{
 argv[i++] = "-Cgidirs";
 argv[i++] = tolower(p);
}
else
{
 v = my_cgi_dirs();
 n = 0;
 if (! isnull(v))   n = max_index(v);
 if (n > 0)
 {
  l = "";
  for (j = 0; j < n; j ++)
  {
   l = strcat(l, v[j]);
   if (! match(string: v[j], pattern: "*/")) l = strcat(l, "/");
   l = strcat(l, " ");
  }
  argv[i++] = "-Cgidirs";
  argv[i++] = l;
 }
}

httpver = get_kb_item("http/"+port);
if (httpver == "11")
{
  argv[i++] = "-vhost";
  argv[i++] = get_host_name();
}

display='';
l = make_list("Display: 1 Show redirects", 
	"Display: 2 Show cookies received",
	"Display: 3 Show all 200/OK responses", 
	"Display: 4 Show URLs which require authentication",
	"Display: V Verbose Output");

foreach var opt (l)
{
 p = script_get_preference(opt);
 if ("yes" >< p) display = strcat(display, substr(opt, 9, 9));
}

if (display)
{
 argv[i++] = "-Display";
 argv[i++] = display;
}

mutate = '';
l = make_list("Mutate: 1 Test all files with all root directories",
	"Mutate: 2 Guess for password file names",
	"Mutate: 3 Enumerate user names via Apache (/~user type requests)",
	"Mutate: 4 Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)");
foreach opt (l)
{
 p = script_get_preference(opt);
 if ("yes" >< p) mutate = strcat(mutate, substr(opt, 8, 8));
}
if (strlen(mutate) > 0)
{
 argv[i++] = "-mutate";
 argv[i++] = mutate;
}

p = script_get_preference("Pause between tests (s)");
p = int(p);
if (p > 0)
{
 argv[i++] = "-Pause";
 argv[i++] = p;
}

p = script_get_preference("Root directory");
if (strlen(p) > 0)
{
 argv[i++] = "-root";
 argv[i++] = p;
}


l = make_list("Tuning: 1 Interesting File / Seen in logs",
	"Tuning: 2 Misconfiguration / Default File",
	"Tuning: 3 Information Disclosure",
	"Tuning: 4 Injection (XSS/Script/HTML)",
	"Tuning: 5 Remote File Retrieval - Inside Web Root",
	"Tuning: 6 Denial of Service",
	"Tuning: 7 Remote File Retrieval - Server Wide",
	"Tuning: 8 Command Execution / Remote Shell",
	"Tuning: 9 SQL Injection",
	"Tuning: 0 File Upload",
	"Tuning: a Authentication Bypass",
	"Tuning: b Software Identification",
	"Tuning: c Remote Source Inclusion",
	"Tuning: x Reverse Tuning Options (i.e., include all except specified)");
tuning= '';
foreach opt (l)
{
 p = script_get_preference(opt);
 if ("yes" >< p) tuning = strcat(tuning, substr(opt, 8, 8));
}
if (strlen(tuning) > 0)
{
 argv[i++] = "-Tuning";
 argv[i++] = tuning;
}


p = int(get_preference("checks_read_timeout"));
if (p > 0)
{
 argv[i++] = "-timeout";
 argv[i++] = p;
}

argv[i++] = "-host"; argv[i++] = get_host_ip();
argv[i++] = "-port"; argv[i++] = port;

encaps = get_port_transport(port);
if (encaps > 1) argv[i++] = "-ssl";

#p = script_get_preference("Force scan all possible CGI directories");
#if ("yes" >< p) argv[i++] = "-allcgi";
p = script_get_preference("Force full (generic) scan");
if ("yes" >< p) argv[i++] = "-generic";

if (idx && idx != "X")
{
  argv[i++] = "-evasion";
  argv[i++] = ids[0];
}

if (user)
{
  if (pass)
    s = strcat(user, ':', pass);
  else
    s = user;
  argv[i++] = "-id";
  argv[i++] = s;
}

r = pread_wrapper(cmd: cmd, argv: argv, cd: 1);
if (! r)
{
 s = '';
 for (i = 0; ! isnull(argv[i]); i ++) s = strcat(s, argv[i], ' ');
 display('Command exited in error: ', s, '\n');
 exit(0, "Command exited with an error.");	# error
}
if ("No HTTP(s) ports found" >< r) exit(0, "Nikto did not find any HTTP ports.");

report = '\nHere is the Nikto report :\n\n';
foreach l (split(r))
{
  #display(j ++, "\n");
  l = ereg_replace(string: l, pattern: '^[ \t]+', replace: '');
  if (l[0] == '+' || l[0] == '-' || ! match(pattern: "ERROR*", string: l))
    report += l;
}

security_note(port: port, extra: report);
if (COMMAND_LINE) display(report, '\n');
