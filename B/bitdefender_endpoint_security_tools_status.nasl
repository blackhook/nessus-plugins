#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136760);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/06");

  script_name(english:"BitDefender Endpoint Security Tools Status (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but problems
 were identified with the installation");
  script_set_attribute(attribute:"description", value:
"BitDefender Endpoint Security Tools, a commercial antivirus software 
package for Windows, is installed on the remote host.  However, 
problems were found with the installation");
  script_set_attribute(attribute:"see_also", value:"https://www.bitdefender.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Updates to security software are critical.");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitdefender:endpoint_security_tools");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_categories", value:"security_control");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bitdefender_endpoint_security_tools_installed.nbin");
  script_require_keys("Antivirus/Bitdefender Endpoint Security Tools/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("antivirus.inc");
include("security_controls.inc");

var kb_base, app, prod_path, prod_ver, eng_ver, sigs, txt_sigs_gmt, cpe,
report, concern, trouble, services, running, servcrit, servwarn, port,
info, sigs_vendor, gmt_vendor, vendor_engine_version, sigwarn, sigcrit;

kb_base = "Antivirus/Bitdefender Endpoint Security Tools";

app = get_kb_item_or_exit(kb_base+"/installed");

app = get_kb_item(kb_base+"/Product");
prod_path = get_kb_item(kb_base+"/Path");
prod_ver = get_kb_item(kb_base+"/Version");
eng_ver = get_kb_item(kb_base+"/Engine");
sigs = get_kb_item(kb_base+"/Sigs");
txt_sigs_gmt = get_kb_item(kb_base+"/Update_time");

cpe = "cpe:/a:bitdefender:endpoint_security_tools";
dbg::detailed_log(lvl:1, msg: crap(data:"=", length:70)+'\n');
dbg::detailed_log(lvl:1, msg:' system product path : ' +  obj_rep(prod_path) + '\n\n');
dbg::detailed_log(lvl:1, msg:' system product version : ' +  obj_rep(prod_ver) + '\n\n');
dbg::detailed_log(lvl:1, msg:' system engine version : ' +  obj_rep(eng_ver) + '\n\n');
dbg::detailed_log(lvl:1, msg:' system sigs : ' +  obj_rep(sigs) + '\n\n');
dbg::detailed_log(lvl:1, msg:' system latest update time : ' +  obj_rep(txt_sigs_gmt) + '\n\n');
dbg::detailed_log(lvl:1, msg: crap(data:"=", length:70)+'\n');
if (empty_or_null(sigs))
  sigs = "unknown";

if (sigs != "unknown")
  sigs = int(sigs);

if (empty_or_null(eng_ver))
  eng_ver = "unknown";


report = "BitDefender Endpoint Security is installed on the remote host :

  Product name      : " + app + "
  Version           : " + prod_ver + "
  Installation path : " + prod_path + "
  Signature number  : " + sigs + "
  Engine version    : " + eng_ver + "
";

concern = 0;
trouble = 0;

# - services running.
services = tolower(get_kb_item("SMB/svcs"));
if (services)
{
  running = FALSE;
  ## Need to double check if bitdefender endpoint agent was removed
  if (
    ("bitdefender endpoint security service" >< services) &&
    ("bitdefender endpoint update service" >< services) &&
    ("bitdefender endpoint integration service" >< services) &&
    ("bitdefender endpoint redline service" >< services) &&
    ("bitdefender endpoint protected service" >< services)
  )
  {
    running = TRUE;
  }

  if (!running)
  {
    if ("bitdefender endpoint security service" >!< services)
    {
      servcrit += '\nBitDefender is installed but BitDefender Endpoint Security Service is not running.\n';
      trouble++;
    }
    else
    {
      servwarn = '\nAt least one of the BitDefender services is not running.\n';
      concern++;
    }
  }
}
else
{
  servwarn += '\nNessus was unable to retrieve a list of running services from the host.\n';
  concern++;
}

if (running)
  running = "yes";
else
  running = "no";

security_controls::endpoint::register(
  subtype                : 'EPP',
  vendor                 : 'BitDefender',
  product                : app,
  product_version        : prod_ver,
  cpe                    : cpe,
  path                   : prod_path,
  running                : running,
  signature_version      : int(sigs),
  signature_autoupdate   : 'unknown'
);


port = get_kb_item('SMB/transport');
if(!port) port = 445;

info = get_av_info("bitdefender");
if (isnull(info)) exit(1, "Failed to get BitDefender antivirus info from antivirus.inc.");

dbg::detailed_log(lvl:1, msg: crap(data:"=", length:70)+'\n');
sigs_vendor = int(info["sigs_vendor"]);
dbg::detailed_log(lvl:1, msg:' vendor latest signature : ' +  obj_rep(sigs_vendor) + '\n\n');

gmt_vendor = int(info["sigs_gmt_vendor"]);
dbg::detailed_log(lvl:1, msg:' vendor latest update time GMT : ' +  obj_rep(gmt_vendor) + '\n\n');

vendor_engine_version = info["sigs_version"];
dbg::detailed_log(lvl:1, msg:' vendor latest engine version : ' +  obj_rep(vendor_engine_version) + '\n\n');
dbg::detailed_log(lvl:1, msg: crap(data:"=", length:70)+'\n');

if (sigs == "unknown")
{
  sigwarn = strcat('\nThe remote host has an unknown',
  ' version of the Bitdefender Endpoint Security Tools',
  ' virus engine.  The latest version recorded by Nessus is ', vendor_engine_version,
  ', updated at ', strftime(gmt_vendor) + '.  ',
  'As a result, the remote host might be infected by viruses.\n');
  concern++;
}

if (eng_ver != "unknown" && eng_ver < vendor_engine_version)
{
  sigcrit = strcat('\nThe remote host has an out-dated version (',
  eng_ver , ') of the Bitdefender Endpoint Security Tools virus engine. ',
  '  The latest version is ', vendor_engine_version, '.  ',
  'As a result, the remote host might be infected by viruses.\n');
  trouble++;
}

if (trouble)
{
  # main service not running
  if (!empty_or_null(servcrit))
    report += servcrit;
  if (!empty_or_null(sigcrit))
    report += sigcrit;

  # nb: antivirus.nasl uses this in its own report.
  set_kb_item(name:kb_base + "/description", value:report);
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else if (concern)
{
  # only 'secondary services not running' to report
  if (!empty_or_null(servwarn))
    report += servwarn;

  # signature version unknown or
  # signature version identified, but out-of-date
  if (!empty_or_null(sigwarn))
    report += sigwarn;

  # nb: antivirus.nasl uses this in its own report.
  set_kb_item(name:kb_base + "/description", value:report);
  exit(0, "Detected BitDefender Endpoint Security.  " + report);

}
else
{
  # nothing bad to report
  report = "Detected BitDefender Endpoint Security with no known issues to report.";
  set_kb_item(name:kb_base + "/description", value:report);

  exit(0, report);
}

exit(0);
