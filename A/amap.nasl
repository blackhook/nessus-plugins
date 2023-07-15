#TRUSTED 115a37f58f19de100c534219fe2449f8674ae7c40b3088f0b56169719aeb1b4a7d6cceb4d5b8a26f0b73adc2f0415692dfe0fad987ad4d001677187dd7af7a9d8c4bb40d87267493fc2de57ec9d417db246aef5eacb4da157ea6d59b57e9a5c65c6381e29b8e6d9465ad892d09cfc658aabfa592ccf88d9ac1e786fb1deb21e6a88e104250b9c76cbc87bf77450a097a8eb5d1c1e3e1ea02514081ef3ee7ef8069ffe6e1ceaa351c656e4ca65c6c35d89db763e7a1d1539950e2575f0d360b3415c7676dda36de21e36a1a1225edfaeb0649caae47c825a0aab6d72c7f5171118666c32f6a6bc6968c3bcc01157392202ad22daba08bf68fb64c832ac4dd43beeb858d432fcc440e14456580d4da8816ca0130098631336124639810ba3215effd683ae950701cb25d76633ae473f75c48a689dd2cd4d865ac0ab12ff315a10c72d84875e91b335871fdc7a6f49af47e5ec4477f1c29c70738499dace08dcaf107aef61aae8228a3e48c1568d2859a99fd658cb94a3df218dbb606184532148bff6991174099fda760f23458716a68d1099be867065e59d62ee13b5151241f5e36b9efed6b853b4e22c621f3d623ea4288a20840e9a9e9ebcc9507ff6f79f89c0b39454ec96e7b8b07c03f9831df5f01e853012c0227060f2d3b5af54c5c500f3303f280684173ff9b786894fea49cb02472c03e0de91dee51a88231cf46b515
#TRUST-RSA-SHA256 4243ea8900cbe771a0a54a3787f48366fe110ab9c4f431495ae741010328c1f013c95e01904290be7ae2015cfe189fb3e798f1ef769e0834723d35a721286f18ebe0c0a352adafb5abecfa1c352e3a8c1dee59f88ff1b7a42f355732915a05ddf4fe55b03d8a6fd16bfe1230fb6fc4fb81b913bb2017f5b0939db5bb5750f8410dbdea1b6c4ade0d1d64834dceb92639a860a4fe02478b2d41f3ace48b0a3d915d6ddde92e8d739f671050ee1474fb57fcb15afa2a39560756edd392a31a8f5f29f8a219257cf5332c8ae7a1a32f57d786bacf309d9a901cfb6288c6a54b28d8ef83145a432679d4f402c00adf6a757086ded150f38f612d30e019732b3d3c7641ebe917108a71f2d69cf5ac620708b5f173038582964916023754d4d184475458662ca5bc8105eb7c92f952d66e7f4797d4e3d90235ee4675b59a2a6baf14893336c4596577a15b5368a43162c09652950e1321a92ea327d7c4cfa2af4136308cf800fe38f3002d62a287c871bad6c3e4cf23313134674e282b8f781bc7f68677bad2008457c0c90a6298f3dbf143f4aac4f3871e2f518386d69aa904705350b7d6de3a34f3c3d2e15761d7e01d7159c655f1a72b676dc19809cc811083a4a6cbf1cfdcb0b094e4f4b913dbb6e7db084cb892b315f0a0595ef55b1a95b030f8ffe114e69705dc0e4adc29be6ce3425ffb8f7a781f54f89c83977d97a3cc4430
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14663);
 script_version("1.32");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_name(english: "amap (NASL wrapper)");
 script_summary(english: "Performs portscan / RPC scan / application recognition"); 

 script_set_attribute(
  attribute:"synopsis",
  value:"This plugin performs application protocol detection."
 );
 script_set_attribute(
  attribute:"description",
  value:
"This plugin runs amap to find open ports and identify applications on
the remote host. 

See the section 'plugins options' to configure it."
 );
 script_set_attribute(attribute:"see_also", value:"http://www.thc.org/thc-amap/");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english: "Port scanners");

 if (NASL_LEVEL >= 3210)
  script_dependencies("portscanners_stub.nasl", "portscanners_settings.nasl");
 else
  script_dependencies("ping_host.nasl", "portscanners_settings.nasl");

 if (NASL_LEVEL < 2181) exit(0);	# Cannot run

 script_add_preference(name: "File containing machine readable results : ", value: "", type: "file");

 script_add_preference(name:"Mode", type:"radio", value: "Map applications;Just grab banners;Port scan only");
 script_add_preference(name:"Quicker", type:"checkbox", value: "no");
 script_add_preference(name:"UDP scan (disabled in safe_checks)", type:"checkbox", value: "no");
 script_add_preference(name:"SSL (disabled in safe_checks)", type:"checkbox", value: "yes");
 script_add_preference(name:"RPC (disabled in safe_checks)", type:"checkbox", value: "yes");

 script_add_preference(name:"Parallel  tasks", type:"entry", value: "");
 script_add_preference(name:"Connection retries", type:"entry", value: "");
 script_add_preference(name:"Connection timeout", type:"entry", value: "");
 script_add_preference(name:"Read timeout", type:"entry", value: "");

 exit(0);
}

if ( ! defined_func("pread") || ! defined_func("fread") ||
     ! defined_func("get_preference") ) exit(0);
if ( ! find_in_path("amap") ) exit(0);

if (NASL_LEVEL < 2181 || ! defined_func("pread") || ! defined_func("get_preference"))
{
  set_kb_item(name: "/tmp/UnableToRun/14663", value: TRUE);
  display("Script #14663 (amap_wrapper) cannot run - upgrade libnasl\n");
  exit(0);
}

global_var tmpnam;

function do_exit()
{
  if (tmpnam) unlink(tmpnam);
}

ip = get_host_ip();
esc_ip = ""; l = strlen(ip);
for (i = 0; i < l; i ++) 
  if (ip[i] == '.')
    esc_ip = strcat(esc_ip, "\.");
  else
    esc_ip = strcat(esc_ip, ip[i]);

res = script_get_preference_file_content("File containing machine readable results : ");
if (res)
  res = egrep(pattern: "^" + esc_ip + ":[0-9]+:", string: res);
if (! res)
{
  # No result, launch amap
  if (get_kb_item("PortscannersSettings/run_only_if_needed")
      && get_kb_item("Host/full_scan")) exit(0);

tmpdir = get_tmp_dir();
if ( ! tmpdir ) do_exit();
tmpnam = strcat(tmpdir, "/amap-", get_host_ip(), "-", rand());

p = script_get_preference("UDP scan (disabled in safe_checks)");
if ("yes" >< p)
 udp_n = 1;
else
 udp_n = 0;

n_ports = 0;

for (udp_flag = 0; udp_flag <= udp_n; udp_flag ++)
{
 i = 0;
 argv[i++] = "amap";
 argv[i++] = "-q";
 argv[i++] = "-U";
 argv[i++] = "-o";
 argv[i++] = tmpnam;
 argv[i++] = "-m";
 if (udp_flag) argv[i++] = "-u";

 p = script_get_preference("Mode");
 if ("Just grab banners" >< p) argv[i++] = '-B';
 else if ("Port scan only" >< p) argv[i++] = '-P';
 else argv[i++] = '-A';

 # As all UDP probes are declared harmful, -u is incompatible with -H
 # Amap exits immediatly with a strange error.
 # I let it run just in case some "harmless" probes are added in a 
 # future version

 if (safe_checks()) argv[i++] = "-H";

 p = script_get_preference("Quicker");
 if ("yes" >< p) argv[i++] = "-1";

 # SSL and RPC probes are "harmful" and will not run if -H is set

 p = script_get_preference("SSL (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-S";
 p = script_get_preference("RPC (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-R";

 p = script_get_preference("Parallel  tasks"); p = int(p);
 if (p > 0) { argv[i++] = '-c'; argv[i++] = p; }
 p = script_get_preference("Connection retries"); p = int(p);
 if (p > 0) { argv[i++] = '-C'; argv[i++] = p; }
 p = script_get_preference("Connection timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-T'; argv[i++] = p; }
 p = script_get_preference("Read timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-t'; argv[i++] = p; }

 argv[i++] = ip;
 pr = get_preference("port_range");
 if (! pr) pr = "1-65535";
 foreach p (split(pr, sep: ',')) argv[i++] = p;

 res1 = pread_wrapper(cmd: "amap", argv: argv, cd: 1, nice: 5);
 res += fread(tmpnam);
 }
}

# IP_ADDRESS:PORT:PROTOCOL:PORT_STATUS:SSL:IDENTIFICATION:PRINTABLE_BANNER:FULL_BANNER

foreach var line(split(res))
{
  v = eregmatch(string: line, pattern: '^'+esc_ip+':([0-9]+):([^:]*):([a-z]+):([^:]*):([^:]*):([^:]*):(.*)$');
  if (! isnull(v) && v[3] == "open")
  {
   scanner_status(current: ++ n_ports, total: 65535 * 2);
   proto = v[2];
   port = int(v[1]); ps = strcat(proto, ':', port);
   scanner_add_port(proto: proto, port: port);
   # As amap sometimes give several results on a same port, we save 
   # the outputs and remember the last one for every port
   # The arrays use a string index to save memory
   amap_ident[ps] = v[5];
   amap_ssl[ps] = v[4];
   amap_print_banner[ps] = v[6];
   amap_full_banner[ps] = v[7];

  }
}

if (n_ports != 0)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: "Host/TCP/scanned", value: TRUE);
 set_kb_item(name: 'Host/scanners/amap', value: TRUE);
 if (pr == '1-65535')
   set_kb_item(name: "Host/full_scan", value: TRUE);
}

if (udp_n && n_ports)
{
  set_kb_item(name: "Host/udp_scanned", value: 1);
  set_kb_item(name: "Host/UDP/scanned", value: 1);
}
  

scanner_status(current: 65535 * 2, total: 65535 * 2);

function cvtbanner(b)
{
  local_var i, l, x;
  l = strlen(b);

  if (b[0] == '0' && b[1] == 'x')
   return hex2raw(s: substr(b, 2));

  x = "";
  for (i = 0; i < l; i ++)
   if (b[i] != '\\')
    x += b[i];
   else
   {
    i++;
    if (b[i] == 'n') x += '\n';
    else if (b[i] == 'r') x += '\n';
    else if (b[i] == 't') x += '\t';
    else if (b[i] == 'f') x += '\f';
    else if (b[i] == 'v') x += '\v';
    else if (b[i] == '\\') x += '\\';
    else display('cvtbanner: unhandled escape string \\'+b[i]+'\n');
   }
  return x;
}

if (! isnull(amap_ident))
 foreach p (keys(amap_ident))
 {
  v = split(p, sep: ':', keep: 0);
  proto = v[0]; port = int(v[1]);
  if (proto == "tcp")
  {
   soc = open_sock_tcp(port);
   if (soc)
    close(soc);
   else
    security_hole(port: port, extra: "Either this port is dynamically allocated or amap killed this service.");

  }
  id = amap_ident[p];
  if (id && id != "unidentified" && id != 'ssl')
  {
   security_note(port: port, proto: proto, extra: "Amap has identified this service as " + id);
   set_kb_item(name: "Amap/"+proto+"/"+port+"/Svc", value: id);
  }

  banner = cvtbanner(b: amap_print_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/PrintableBanner", value: banner);

  banner = cvtbanner(b: amap_full_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/FullBanner", value: banner);
 }


do_exit();
