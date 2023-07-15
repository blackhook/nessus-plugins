#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110642);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-2768", "CVE-2018-2801", "CVE-2018-2806");
  script_bugtraq_id(103815, 103816, 103819);

  script_name(english:"Security Updates for Exchange (Jun 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?819cd7a6");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4295699
  -KB4099855
  -KB4099852");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2768");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_exchange_installed.nbin");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'Microsoft Exchange';
port = kb_smb_transport();

kbs = [
  'KB4295699',
  'KB4099855',
  'KB4099852'
];

report = '';

# Check install and determine fixed version
install = get_single_install(app_name:appname);

path = install["path"];
version = install["version"];
release = install["RELEASE"];

if (release != 140 && release != 150 && release != 151)
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);

if (!empty_or_null(install["SP"]))
  sp = install["SP"];
if (!empty_or_null(install["CU"]))
  cu = install["CU"];

if (release == 140) # Exchange Server 2010 SP3
{
  fixedver = "14.3.411.0";
  kb = kbs[0];
}
else if (release == 150) # Exchange Server 2013
{
  fixedver = "15.0.1395.4";
  kb = kbs[1];
}
else if (release == 151) # Exchange Server 2016
{
  fixedver = "15.1.1531.3";
  kb = kbs[2];
}

if (!fixedver)
  audit(AUDIT_HOST_NOT, 'affected');


# Check version of binary to verify
if ( hcf_init == 0 )
{
  if(hotfix_check_fversion_init() != HCF_OK)
    exit(0, "Could not start an SMB session");
}

dir_path = hotfix_append_path(path:path, value:'Bin');
exe_path = hotfix_append_path(path:dir_path, value:'ExSetup.exe');

if ( hotfix_file_exists(path:exe_path) &&
  hotfix_check_fversion(file:"ExSetup.exe", path:dir_path, version:fixedver) == HCF_OLDER )
{
  report =
      '\n  Path              : ' + exe_path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixedver +
      '\n  Patch             : ' + kb +
      '\n';
}
hotfix_check_fversion_end();

if ( report != '' )
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
else
  audit(AUDIT_INST_VER_NOT_VULN, appname);
