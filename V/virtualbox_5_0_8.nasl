#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{ 
  script_id(86568);
  script_version("1.10");
  script_cvs_date("Date: 2019/03/27 13:17:50");

  script_cve_id("CVE-2015-4813", "CVE-2015-4896");

  script_name(english:"Oracle VM VirtualBox < 4.0.34 / 4.1.42 / 4.2.34 / 4.3.32 / 5.0.8 Multiple Core DoS (October 2015 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
unspecified denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle VM VirtualBox application installed on the remote host is a
version prior to 4.0.34, 4.1.42, 4.2.34, 4.3.32, or 5.0.8. It is,
therefore, affected by multiple unspecified flaws in the Core
subcomponent. A local attacker can exploit these to cause a denial of
service.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 4.0.34 / 4.1.42 / 4.2.34 /
4.3.32 / 5.0.8 or later as referenced in the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4896");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app  = NULL;
apps = make_list('Oracle VM VirtualBox', 'VirtualBox');

foreach app (apps)
{
  if (get_install_count(app_name:app)) break;
  else app = NULL;
}

if (isnull(app)) audit(AUDIT_NOT_INST, 'Oracle VM VirtualBox');
  
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver  = install['version'];
path = install['path'];

# Note int(null) returns '0'
ver_fields = split(ver, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev   = int(ver_fields[2]);

fix = '';

# Affected :
# 4.0.x < 4.0.34
# 4.1.x < 4.1.42
# 4.2.x < 4.2.34
# 4.3.x < 4.3.32
# 5.0.x < 5.0.8
if      (major == 4 && minor == 0 && rev < 34) fix = '4.0.34';
else if (major == 4 && minor == 1 && rev < 42) fix = '4.1.42';
else if (major == 4 && minor == 2 && rev < 34) fix = '4.2.34';
else if (major == 4 && minor == 3 && rev < 32) fix = '4.3.32';
else if (major == 5 && minor == 0 && rev < 8)  fix = '5.0.8';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
