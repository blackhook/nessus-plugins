#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92459);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-3597");

  script_name(english:"Oracle VM VirtualBox < 5.0.26 Core Subcomponent DoS (July 2016 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Oracle VM VirtualBox application installed on the remote host is a
version prior to 5.0.26. It is, therefore, affected by an unspecified
flaw in the Core subcomponent that allows a local attacker to cause a
denial of service condition.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 5.0.26 or later as referenced
in the July 2016 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3597");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# Affected :
# 5.0.x < 5.0.26
if  (ver =~ '^5\\.0' && ver_compare(ver:ver, fix:'5.0.26', strict:FALSE) < 0) fix = '5.0.26';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
exit(0);
