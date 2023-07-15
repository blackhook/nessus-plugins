#TRUSTED 60a50b775f2c149d6c9773ff68caa772c3f3190c87191364fa3cb3cddaa335e51ea3f5c57cd9a63079639b3b812b1f1c5776077fc6cf4f2448335bf4e5c1843cb2b1c090425eb9a5d729d3abe6647e76b5e39e2475d43ad2284473f63d9bbe8001f54b2d1482c47ede856afbe02a27e2e612e74bcab4b935023157c77e9ac668509d54aeef13aa94e257d38538dfab9c891d7104e8240f1fd6cd9a3ffe3a17bcb2aa792b47a401f45e28791fe3607cf20a2636f9fa82af71a8395aa3c18968db9666c82ef22e974333cb737108127f2743642ee2f4502cb98455ee6eaab00f4289ad0db0524fd0585c74aa95dedfaccab663eada19d9169ba729d967b8a18d7c986546fa040342109053d9b96740eb901deb8278313c7a017b825ce717e3bedb9133d546390d438649aaa5b8e33a5008cd898dc46d73e995403ddb77cebab403c105bf4e3c7007a754f2ea00badaa0a5404a4c17ebf87fda0e4d4d54bcd9dee5cb7e8bd9beb1c17bac469277b47d4c71bde2212ea7447197418d4c8372a752768a8429ae9e8185cca983e227ffecd9183ca106f0f911c38b4d04d972b3f4944e2a5ed2fcbf9594798f5415ee30013632560347aa0dc26b87f3b6854e049b44f01ce43fcd1764a44e98f1fd3d57e22bc138aaf9a60b1c0183ba5291aaf2991bab5b4656bb2175a505064f9a4fd8d1e59cdd8c306e249b43e8273dae7a2476b619
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86610);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2015-7750");

  script_name(english:"Juniper ScreenOS < 6.3.0r20 L2TP DoS (JSA10704)");
  script_summary(english:"Checks version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Juniper ScreenOS prior to
6.3.0r20. It is, therefore, affected by a denial of service
vulnerability related to the handling of L2TP packets. An
unauthenticated, remote attacker can exploit this, via specially
crafted L2TP packet, to cause the system to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10704");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS 6.3.0r20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

##
# Only systems with l2tp configured are vulnerable
##
function l2tp_configured()
{
  local_var ret,buf;

  ret = ssh_open_connection();
  if(!ret)
    exit(1, "ssh_open_connection() failed.");
  buf = ssh_cmd(cmd:'get config | include "l2tp"', nosh:TRUE, nosudo:TRUE, noexec:TRUE, cisco:FALSE);
  ssh_close_connection();
  if("set l2tp" >< tolower(buf))
    return TRUE;
  return FALSE;
}

app_name = "Juniper ScreenOS";
display_version = get_kb_item_or_exit("Host/Juniper/ScreenOS/display_version");
version = get_kb_item_or_exit("Host/Juniper/ScreenOS/version");
csp = get_kb_item("Host/Juniper/ScreenOS/csp");

if(isnull(csp))
  csp = "";

# Remove trialing 'a' if there, no 'a' versions fixes this
version = ereg_replace(pattern:"([0-9r\.]+)a$", replace:"\1", string:version);

# Check version
display_fix = "6.3.0r20";
fix = str_replace(string:display_fix, find:'r', replace:'.');

# CSPs
if(version =~ "^6\.3\.0\.13($|[^0-9])" && csp =~ "^dnd1")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
if(version =~ "^6\.3\.0\.18($|[^0-9])" && csp =~ "^dnc1")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

# If we're not 6.3.x or if we are greater than or at fix version, audit out
if(ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

# We have various version sources for this, not all rely on local checks
note = FALSE; # Similar to cisco caveat
if(!isnull(get_kb_item("Host/local_checks_enabled")))
{
  if(!l2tp_configured())
    audit(AUDIT_HOST_NOT, "affected because l2tp is not enabled");
}
else
{
  note =
   '\n  Note: Nessus could not verify that L2TP is configured because' +
   '\n        local checks are not enabled. Only devices using L2TP'+
   '\n        are potentially vulnerable.';
}

port = 0;
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + display_fix;
  if(note)
    report += note;
  report += '\n';

  security_warning(extra:report, port:port);
}
else security_warning(port);
