#TRUSTED 4c72c3666de8415b6257996488fd63e6511b005be8beb9390835b95924646c05ba150f15e5cfc050ebb565e5bc5014c89bbad945d56aa17e2f31a4f562c73a56b12f20783a41ddcc4fdf476cc03f72bb35634ed51b16d10b83dcfafc1433ebd4d27928e1e9e0ac4645d7a65a5aaf0b806ef4dc6f8ce31ba4395c00d0a44932f027fa6301bc8440bb70e87af2f15f108a8ef79c0a429dce35b325dd78bb15b13167f834fff9bdd480fb657546573f3aa0c60c57838bc17ab66ae2bbdbcd192830c8d2cd358d0673fa0bcae67cf33661ec31c69cde7cf95ca19fa42534c3ad982f75a318263a2a030892f7ae141ea8e8f8dd05436eb59be8bcbcd57a49cdf464aa17f26f0135cb2dbe88f7d35e29291d3a0d2c0a38f944045d028650150611d6ea2dd765a11328f1cca104053040e859a8d072ae576c1762ceb4bdebbc84237d00234784cd827fc6c6b63f8b83690f09c2d8b4848fe2f96a8dec663c351936b7b034398463bfea167b81cc4bd8194cf886fe772f63fd6a4cec0e12f0c3f2b6b2eaca2c503a6a9ce3c20639adcc6d33940be7b66ff3b46c7d5b812240b5cd0554e607c2f42392290ba5fb5ac32bdaa969089a19586067cd5fbb85bc99b0d426a75fd56a9c4d60df0541f80296325a66f7106930b5759e860e39dbb76048ffe5a062e68d0f3345dccffae68fb2bd987ad21e29683ef65ef481ece982f762a205b111
#TRUST-RSA-SHA256 5c1b1ce8cc5ce554a1fae266825d0e10da0f92d55c8dc6c60e353f9437f0c0d10bc249bf7f5c06336cfe7345a9ec0871e72416da8b818638c186b1a7713668282e5911e1237bc3cf94aed4e70f58b3cc98860d36ff6adfc35edde332432c526914b7d016469fc6d113b87b3d6ddc4ba04d49696e0031b0a7b85502e5d405daec9751ac746723a68b9e52d1dfa3688ef954c10aba4033be16a494203ef970219203b8166112a172ee7794005f8d0c6d2f1a24ec2907714a9fab1b5a0d16d1d961cece5ac2c4e21691df58f6be610fdd33cc06b8e0d25233f84fff6d6cceb7dc0c2a01d0e87b8ff9ef39241395ce22c262f249ae087f90886c5541f5447ad668bd6912d0173815cf808835fce99c844080e5416f97b2bae0a1941e72ed88921b04edd253449744e70cf145212cbab5c660e47be4c74ce491079dd7b7b5f0f4f329b7c10e63eda463cc109d126cb40922d9b97d44612982f93027b191632e2cd45b2f457c986fc28e501a859b0df362316c57cfc9cf5fdac7ddfe4635a7bc634d1695c9beee700e378b80526ced3a47b27442d7ea4a05f0cf13035a62bc4080df1543fe267f4f93f1bd512e5bc60b204d8258142b6d7f1ffda126ae07f3768ae6be86cba0123ba9a5ea1283d45e535c37f637d99a066846047a8e21f1f461f066c94b63d749810422a68e62da07272ef505c5c39be08142c8f89ffc1dbaa66e6b13
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15868);
 script_version("1.24");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english:"Hydra (NASL wrappers options)");
 script_summary(english:"Brute force authentication protocols");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin is used to set options for Hydra.");
 script_set_attribute(attribute:"description", value:
"This plugin sets options for the Hydra tests.  Hydra finds passwords
by brute force. 

To use the Hydra plugins, enter the 'Logins file' and the 'Passwords
file under the 'Hydra (NASL wrappers options)' advanced settings
block.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"Brute force attacks");

 script_add_preference(name: "Always enable Hydra (slow)", type:"checkbox", value: "no");
 script_add_preference(name: "Logins file : ", value: "", type: "file");
 script_add_preference(name: "Passwords file : ", value: "", type: "file");
 script_add_preference(name: "Number of parallel tasks :", value: "16", type: "entry");
 script_add_preference(name: "Timeout (in seconds) :", value: "30", type: "entry");
 script_add_preference(name: "Try empty passwords", type:"checkbox", value: "yes");
 script_add_preference(name: "Try login as password", type:"checkbox", value: "yes");
 script_add_preference(name: "Exit as soon as an account is found", type:"checkbox", value: "no");
 script_add_preference(name: "Add accounts found by other plugins to login file", type:"checkbox", value: "yes");

 exit(0);
}

if (!defined_func("script_get_preference_file_location")) exit(0);
if ((!find_in_path("hydra")) && (!file_stat(nessus_get_dir(N_STATE_DIR) + '/feed_build')))
{
  exit(0, "Hydra was not found in '$PATH'.");
}

include("global_settings.inc");
include("misc_func.inc");

function mk_login_file(logins)
{
  local_var	tmp1,tmp2, dir, list, i, u;
  if ( NASL_LEVEL < 2201 )
  {
    display("NASL_LEVEL=", NASL_LEVEL, " - update your Nessus engine!");
    return logins; # fwrite broken
  }
  dir = get_tmp_dir();
  if (! dir)
  {
    display("Could not get tmp dir.");
    return logins;	# Abnormal condition
  }
  dir += '/';
  for (i = 1; TRUE; i ++)
  {
    u = get_kb_item("SMB/Users/"+i);
    if (! u) break;
    list = strcat(list, u, '\n');
  }
# Add here results from other plugins
  if (! list) return logins;
  tmp1 = strcat(dir, 'hydra-'+ get_host_ip() + '-' + rand());
  tmp2 = strcat(dir, 'hydra-'+ get_host_ip() + '-' + rand());
  if (fwrite(data: list, file: tmp1) <= 0)	# File creation failed
  {
    display("Could not write file ", tmp1, ".");
    return logins;
  }
  if (! logins) return tmp1;
  pread_wrapper(cmd: "sort", argv: make_list("sort", "-u", tmp1, logins, "-o", tmp2));
  unlink(tmp1);
  return tmp2;
}

if ("yes" >< thorough_tests)
  set_kb_item(name: "/tmp/hydra/force_run", value: TRUE);
else
{
 p = script_get_preference("Always enable Hydra (slow)");
 if ("yes" >< p)
   set_kb_item(name: "/tmp/hydra/force_run", value: TRUE);
 else
    exit(0, "Hydra scripts will not run unless the 'Perform thorough tests' setting is enabled or 'Always enable Hydra' is set.");
}

if ( ! script_get_preference("Passwords file : ") )
  exit(0, "No passwords file is provided.");
p = script_get_preference_file_location("Passwords file : ");
if (!p ) exit(0, "Hydra passwords file does not exist or is empty.");
if ( NASL_LEVEL >= 5000 )
{
  # Decipher the file
  mutex_lock(SCRIPT_NAME);
  if ( get_kb_item("/tmp/hydra/converted_pw") == NULL )
  {
    b = fread(p);
    fwrite(data:b, file:p);
    set_kb_item(name:"/tmp/hydra/converted_pw", value:TRUE);
  }
  mutex_unlock(SCRIPT_NAME);
}

set_kb_item(name: "Secret/hydra/passwords_file", value: p);

# No login file is necessary for SNMP, VNC and Cisco; and a login file 
# may be made from other plugins results. So we do not exit if this
# option is void.
a = script_get_preference("Add accounts found by other plugins to login file");
if (script_get_preference("Logins file : ") )
  p = script_get_preference_file_location("Logins file : ");
else
  p = NULL;


if ( p != NULL && NASL_LEVEL >= 5000 )
{
  # Decipher the file
  mutex_lock(SCRIPT_NAME);
  if ( get_kb_item("/tmp/hydra/converted_lg") == NULL )
  {
    b = fread(p);
    unlink(p);
    fwrite(data:b, file:p);
    set_kb_item(name:"/tmp/hydra/converted_lg", value:TRUE);
  }
  mutex_unlock(SCRIPT_NAME);
}

if ("no" >!< a) p = mk_login_file(logins: p);


set_kb_item(name: "Secret/hydra/logins_file", value: p);

p = script_get_preference("Timeout (in seconds) :");
t = int(p);
if (t <= 0) t = 30;
set_kb_item(name: "/tmp/hydra/timeout", value: t);

p = script_get_preference("Number of parallel tasks :");
t = int(p);
if (t <= 0) t = 16;
set_kb_item(name: "/tmp/hydra/tasks", value: t);

p = script_get_preference("Try empty passwords");
if ( "yes" >< p )
  set_kb_item(name: "/tmp/hydra/empty_password", value: TRUE);

p = script_get_preference("Try login as password");
if ( "yes" >< p )
 set_kb_item(name: "/tmp/hydra/login_password", value: TRUE);

p = script_get_preference("Exit as soon as an account is found");
if ( "yes" >< p ) 
 set_kb_item(name: "/tmp/hydra/exit_ASAP", value: TRUE);


# Collect some info about the installed version of Hydra.
results = pread_wrapper(cmd:"hydra", argv:make_list("hydra"), nice:5);
foreach var line (split(results, keep:FALSE))
{
  # - version.
  v = eregmatch(string:line, pattern:'^[ \t]*Hydra v([0-9][^ \t]+)[ \t]');
  if (!isnull(v))
  {
    set_kb_item(name:"Hydra/version", value:v[1]);
    continue;
  }

  # - syntax line (to diagnose problems).
  v = eregmatch(string:line, pattern:'^[ \t]*Syntax[ \t]*:');
  if (!isnull(v))
  {
    set_kb_item(name:"Hydra/syntax", value:line);
    continue;
  }

  # - supported services.
  v = eregmatch(string:line, pattern:'^[ \t]*service[ \t]+.*Supported protocols[ \t]*:[ \t]+(.+)$');

  # Newer versions of Hydra have moved the supported services line
  if (empty_or_null(v))
  v = eregmatch(string:line, pattern:'^[ \t]*Supported services[ \t]*:[ \t]+(.+)$');

  if (!isnull(v))
  {
    svcs = v[1];
    set_kb_item(name:"Hydra/services", value:svcs);

    svcs = str_replace(find:"ftp[s]", replace:"ftp ftps", string:svcs);
    svcs = str_replace(find:"http[s]-{head|get}", replace:"https-head https-get http-head http-get", string:svcs);
    svcs = str_replace(find:"http-{head|get}", replace:"http-head http-get", string:svcs);
    svcs = str_replace(find:"http[s]-{head|get|post}", replace:"https-head https-get https-post http-head http-get http-post", string:svcs);
    svcs = str_replace(find:"http-{head|get|post}", replace:"http-head http-get http-post", string:svcs);
    svcs = str_replace(find:"http[s]-{get|post}-form", replace:"https-get-form https-post-form http-get-form http-post-form", string:svcs);
    svcs = str_replace(find:"http-{get|post}-form", replace:"http-get-form http-post-form", string:svcs);
    svcs = str_replace(find:"ldap3[-{cram|digest}md5]", replace:"ldap3 ldap3-crammd5 ldap3-digestmd5", string:svcs);
    svcs = str_replace(find:"mysql(v4)", replace:"mysql", string:svcs);

    foreach var svc (split(svcs, sep:" ", keep:FALSE))
    {
      set_kb_item(name:"/tmp/hydra/service/"+svc, value:TRUE);
    }
    continue;
  }
}
