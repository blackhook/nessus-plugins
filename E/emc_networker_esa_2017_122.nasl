#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104178);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-8022");
  script_bugtraq_id(101551);

  script_name(english:"EMC NetWorker < 8.2.4.9 / 9.x < 9.1.1.3 / 9.2.x < 9.2.0.4");
  script_summary(english:"Checks the version of EMC NetWorker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC NetWorker installed on the remote Windows host is
prior to 8.2.4.9 or 9.x prior to 9.1.1.3 or 9.2.x prior to
9.2.0.4. It is, therefore, affected by a buffer overflow
vulnerability. A remote, unauthenticated attacker may potentially
exploit this vulnerability to execute arbitrary code or cause a
denial of service condition, depending on the target systems platform.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Oct/35");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC NetWorker 8.2.4.9 / 9.1.1.3 / 9.2.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8022");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname  = "EMC NetWorker";
install  = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];
build    = install['Build'];
server   = install['Server'];

if(server != 1) audit(AUDIT_INST_VER_NOT_VULN, "EMC NetWorker Client");

fix = NULL;
if (ver_compare(ver:version, fix:'8.2.4.9', strict:FALSE) < 0)
  fix = '8.2.4.9';
else if (version =~ "^9\.[0-1]\." && ver_compare(ver:version, fix:'9.1.1.3', strict:FALSE) < 0)
  fix = '9.1.1.3';
else if (version =~ "^9\.2\." && ver_compare(ver:version, fix:'9.2.0.4', strict:FALSE) < 0)
  fix = '9.2.0.4';

if (isnull(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, 'EMC NetWorker', version, path);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
