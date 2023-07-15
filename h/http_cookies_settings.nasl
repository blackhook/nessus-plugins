#TRUSTED a710ab0f731b5407533e75849d213d2b683c4a4019ce4d62a66f5662e24d0dd688f3c02e2829b0ae9c5a90f993a29f5c6b2a4af23b183986d0ea0e502d981443dcb98e5c7f358584fead0f57f7124988c18012ae7b07d3fd2788c44de85903018f2d5bc865edd2f170f518f0260fb6a0ebf16f22f537d877c5805c032a7621f927499a5204d8282dbfad6a1770f7a3ace06339ae582711602bf9ec218686e35c32d2de35cf3bdfa4e2a71d9bf50a062582d9c0bc753332034e76bd005c5192c068ecf8cd2cb30b0b33bb48686b98c5bd6ad2f317d8b16671c053a7528c0d9c1cbd561ad06d5cb2a1884c48a3782999b6ee4e1db237d62893ba50d8b2f16c373edc60b56eae964996733ea205e0ae620bebf555d520cca48a9e346851b862059b7466376da733c7a992287a2cc9c801b408feb7a084a331adbe19b3b3b12f227c0b254cb545bc4e4c9d5d142b333a57471b0a7cde32b6fa9324184627bb051f39311e078745d443c36fc11757c717d54a0ec387f592b4b4be85ba8707d9d210195401051647bc8f191308dc09c97020592378cd85f5d68f93eee5c5bd8aa69d6cd45325a80bb2134a687dd2a349820108118e22e1ee27c336fad56cd831b734de9cb985ac797de14a08364b367d0bb72b88d27ab9a62b0448cc4a715fe98dd34f4aa15ea847810628282de1531c7f0e2d00d89978d538cd9f2eb4061cd8f7479f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42893);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/15");

 script_name(english:"HTTP cookies import");
 script_summary(english:"Import HTTP cookies in Netscape format");

 script_set_attribute(attribute:"synopsis", value: "HTTP cookies import.");
 script_set_attribute(attribute:"description", value:
"This plugin imports cookies for all web tests.

The cookie file must be in 'Netscape format'.

It does not perform any test by itself.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/25");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_category(ACT_SETTINGS);
 script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 script_add_preference(name: "Cookies file : ", type: "file", value:"");
 script_dependencies("ping_host.nasl", "global_settings.nasl");
 exit(0);
}

include("misc_func.inc");

global_var	same_hosts_l;
same_hosts_l = make_array();

function _wm_same_host(h)
{
 local_var	n, i;
 n = tolower(get_host_name());
 if (n == h) return 1;
 i = get_host_ip();
 if (i == h) return 1;

 # Do not call same_host, it was broken
 return 0;
}

function wm_same_host(h)
{
 h = tolower(h);
 if (same_hosts_l[h] == 'y') return 1;
 if (same_hosts_l[h] == 'n') return 0;
 if (_wm_same_host(h: h))
 {
  same_hosts_l[h] = 'y';
  return 1;
 }
 else
 {
  same_hosts_l[h] = 'n';
  return 0;
 }
}

#### Functions from http_cookie_jar.inc, to avoid signing it

global_var	CookieJar_value, CookieJar_version, CookieJar_expires,
		CookieJar_comment, CookieJar_secure, CookieJar_httponly,
		CookieJar_domain, CookieJar_port,
		CookieJar_is_disabled, CookieJar_autosave;

function set_http_cookie(key, name, path, value, domain, secure, version)
{
  if (isnull(key))
  {
    if (isnull(name))
    {
      err_print("set_http_cookie: either key or name must be set!\n");
      return NULL;
    }
    if (! path) path = "/";
    key = strcat(name, '=', path);
  }
  else
  {
    if (! isnull(name))
      err_print("set_http_cookie: key (", key, ") and name (", name, ") cannot be both set! Ignoring name.\n");
  }
  CookieJar_value[key] = value;
  if (isnull(version)) version = 1;
  CookieJar_version[key] = version;
  CookieJar_domain[key] = domain;
  # CookieJar_expires[key] = NULL;
  # CookieJar_comment[key] = NULL;
  if (strlen(CookieJar_autosave) > 0)
    store_1_cookie(key: key, jar: CookieJar_autosave);
}

function store_1_cookie(key, jar)
{
  local_var	val, kbkey;

  kbkey = hexstr(key);
  if (isnull(jar)) jar = "Generic";
  val = CookieJar_value[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/value/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/value/"+kbkey);

  val = CookieJar_version[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/version/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/version/"+kbkey);

  val = CookieJar_expires[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/expires/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/expires/"+kbkey);

  val = CookieJar_comment[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/comment/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/comment/"+kbkey);

  val = CookieJar_secure[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/secure/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/secure/"+kbkey);

  val = CookieJar_httponly[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/httponly/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/httponly/"+kbkey);

  val = CookieJar_domain[key];
  if (! isnull(val))
    replace_kb_item(name: "Cookies/"+jar+"/domain/"+kbkey, value: val);
  else if (defined_func("rm_kb_item"))
    rm_kb_item(name: "Cookies/"+jar+"/domain/"+kbkey);
}

function store_cookiejar()
{
  local_var	k;
  if (isnull(CookieJar_value)) return;
  foreach k (keys(CookieJar_value))
     store_1_cookie(key: k, jar: _FCT_ANON_ARGS[0]);
}

#### end of cookie functions

# Import Netscape cookies

if (script_get_preference("Cookies file : ")) # Avoid dirty warning
  content = script_get_preference_file_content("Cookies file : ");
else
  exit(0, "No cookie file.");

n = 0;
if (strlen(content) > 0)
{
  CookieJar_autosave = NULL;

  lines = split(content, keep: 0);
  content = NULL;	# Free memory
  now = unixtime();

  foreach l (lines)
  {
    if (l =~ '^[ \t]*#') continue; # ignore comments
    if (l =~ '^[ \t]*$') continue; # ignore all whitespace lines
# Fields:
# 0 domain
# 1 flag - indicates if all machines within a given domain can access the variable.
# 2 path
# 3 secure
# 4 expiration - UNIX time
# 5 name
# 6 value
    v = split(l, sep: '\t', keep: 0);
    m = max_index(v);

    if (m < 6 || m > 8)
      exit(1, 'Invalid cookies file (unexpected line).');

    if (v[3] == "TRUE") sec = 1; else sec = 0;
    t = int(v[4]);	# Expiration date

    # nb: Firebug has 8 fields per line, with a field for max-age between 
    #     expiration and cookie name.
    if (m == 8)
    {
      name = v[6];
      val =  v[7];
    }
    else
    {
      name = v[5];
      val =  v[6];
    }

    # Import session cookies, but reject expired cookies
    if (t == 0 || now < t)
    {
      set_http_cookie(path: v[2], domain: v[0], secure: sec, name:name, value:val);
      n ++;
    }
    else
      dbg::detailed_log(lvl: 3, src: SCRIPT_NAME,
          msg:"Expired cookie: t="+ t +" Path="+ v[2] +" Domain="+ v[0] +" Secure="+ sec +" Name="+ name+ " Value="+ val);
  }

  if (n == 0)
    exit(1, 'No cookies were found in the given file.');

  dbg::detailed_log(lvl:1, src: SCRIPT_NAME, msg:n+" cookies imported.");
  # It is not always related to authentication, but this will be the main use
  store_cookiejar("FormAuth");
  store_cookiejar();
  lines = NULL;	# Free memory
}
else
  exit(0, "Cookie file is empty.");

