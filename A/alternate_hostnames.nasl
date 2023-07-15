#TRUSTED 15792886d1c6728a8860a180aab752d3fda78a6aeca90b876b12ba27a712f9862e456ad57c496aab189c3441a54597088da709af565db23d5fe43313bb9f20239cb545190e70fcfa4ad69a8e3ef310f6e32d8c668e01481191f3019a5eeef67867d4858bed6090fd637987bf3a2fa052a76c5cb3313dc5fe98607363a6ab5f7bd331d4935752f875359f0f7ba0b7e979a28b031a9c67691b7a2acbdfde6eda15e408e7663d49539ef12de634eb04c278ef199e4637a654821138ad2f68ed38998cb6bb2b49c3e994b402bf00f08d161f150a697184d66ba6d5c2c93c048094cb43fa48a9ac435535eaaa97138b422ca75f5e85aa891813be9bbb52550f94c8d828352d025108cbe042ca5d1cab207900a22e10530f0ddafd95ff0b808c6ae35c0b28836a1929324f93a4766d7d18de489a6fc3f54c2125628adf87cb27c87c30c181a2a78ee9f7ad44c7ade311c362d19a575899b0a57beb9b34475bb7cc394af738a69a37dc3315ff2a68c2a4ca2237dffa5ff76e2d40f4f7bdc8571475598ef99edceedbb2b683cebc5b57fae0da7eb44d606622c54984710b1f3d7673564c35c4c221569550bd502112f189082333af12da10d0ea26401aeb1d07b98618c88a10f981848b6ceedf19a47154aa7fe29db8dbdf51cb9ff92621e8d149176c5645878fe97b7fc261273e4c08e0639fcefb7e2ae44eaf31ec9d6e0e01c10bb200
#
# (C) Tenable Network Security, Inc.
#

# This plugin uses data collected by webmirror.nasl and others.

if ( NASL_LEVEL < 4200 ) exit(0);
include("compat.inc");

if(description)
{
 script_id(46180);
 script_version("1.18");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/15");

 script_name(english:"Additional DNS Hostnames");
 script_summary(english:"Reports all found vhosts.");
 
 script_set_attribute(attribute:"synopsis", value:
"Nessus has detected potential virtual hosts.");
 script_set_attribute(attribute:"description", value:
"Hostnames different from the current hostname have been collected by
miscellaneous plugins. Nessus has generated a list of hostnames that
point to the remote host. Note that these are only the alternate
hostnames for vhosts discovered on a web server.

Different web servers may be hosted on name-based virtual hosts.");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Virtual_hosting");
 script_set_attribute(attribute:"solution", value:
"If you want to test them, re-scan using the special vhost syntax,
such as :

www.example.com[192.0.32.10]");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencie("webmirror.nasl", "ssl_cert_CN_mismatch.nasl", "bind_hostname.nasl", "netbios_name_get.nasl");
 script_require_keys("Services/www");
 exit(0);
}

include("misc_func.inc");
include("resolv_func.inc");

global_var	name, seen, tested, report, nb, domain;

function test(h)
{
  h = tolower(h);
  if (h != name && ! seen[h])
  {
    seen[h] = 1; tested ++;
    if (is_same_host(a: h))
    {
      report = strcat(report, '  - ', h, '\n');
      set_kb_item(name:"Host/alt_name", value: h);
      nb ++;
    }
  }

  if (domain && "." >!< h)
  {
    h = h + domain;
    if (h != name && ! seen[h])
    {
      seen[h] = 1; tested ++;
      if (is_same_host(a: h))
      {
        report = strcat(report, '  - ', h, '\n');
        set_kb_item(name:"Host/alt_name", value: h);
        nb ++;
      }
    }
  }
}

www = get_kb_list("Services/www");
if ( isnull(www) ) exit(0, "No web server was found.");

begin = unixtime();

name = get_host_name(); name = tolower(name);
ip = get_host_ip();

report = ""; n = 0;  tested = 0;
seen = make_array(name, 1, ip, 1);

h = rand_str(); tested ++;
if (is_same_host(a: h)) exit(1, "The resolver is broken.");

# Hostnames found by the web crawler.
l = get_kb_list("webmirror/*/hosts");
if (! isnull(l))
  foreach h (make_list(l))
    test(h: h);

# Extract domain name (with a leading dot)
domain = NULL;
if (name != ip)
{
  v = eregmatch(string: name, pattern: "^([^.]+)(\..+\.?)$");
  if (! isnull(v))
  {
    domain = tolower(v[2]);
    h = rand_str(charset:"abcdefghijklmnopqrstuvwxy", length:6); tested ++;
    if (is_same_host(a: h + domain))
    {
      dbg::detailed_log(lvl:2, msg:"DNS wildcard on domain "+domain);
      domain = NULL;
    }
  }
}

# BIND hostname, SMB name ...
foreach k (make_list("bind/hostname", "SMB/name"))
{
  h = get_kb_item(k);
  if (! isnull(h)) test(h: h);
}

# CN from X509 certificates.
names = make_list();
l = get_kb_list("X509/*/CN");
if (! isnull(l)) names = make_list(names, l);
l = get_kb_list("X509/*/altName");
if (! isnull(l)) names = make_list(names, l);
l = NULL;

foreach h (names) test(h: h);

# Banners from services.
l = get_kb_list("*/banner/*");
if (! isnull(l))
{
  l = make_list(l);
  foreach banner (l)
  {
    if (strlen(banner) > 200) continue;
    foreach line (split(banner, keep: 0))
    {
      while (line != "")
      {
        v = eregmatch(string: line, icase: 1, pattern: "(^|[ :,;@])(([a-z_][a-z0-9_-]*)(\.[a-z_][a-z0-9_-]*)*)(.*)" );
        if (isnull(v)) break;
	test(h: v[2]);
	line = v[5];
      }
    }
  }
  l = NULL;
}

# Brute force.
if (domain)
{
  now = unixtime();
  # Name resolutions take less than 1 s?
  if (now - begin <= tested)
  {
    l = make_list( "smtp", "mta", "pop", "imap", "pop2", "pop3", 
"ads", "backend", "blog", "blogs", "bugs", "careers", 
"cgi", "commumity", "communities", "connect", "corporate", "developer", 
"docs", "download", "downloadcenter", "downloads", "forum", "global", 
"investor", "investors", "jobs", "list", "lists", "mail", "media", "my", 
"news", "press", "public", "remote", "remote-access", "research", "resources",
"search", "services", "shopping", "software", "store", "stores", "support", 
"supportcentral", "video", "videos", "vpn", "vpnaccess", "webmail", "welcome",
"www1", "www2");
    foreach h (l)
    {
      h += domain;
      test(h: h);
    }
    l = NULL;
  }
}

if (nb == 0) exit(0, "No new DNS hostname was found.");
report = 'The following hostnames point to the remote host :\n' + report;
security_note(port:0, extra:report);
if (COMMAND_LINE) display(report, '\n');
