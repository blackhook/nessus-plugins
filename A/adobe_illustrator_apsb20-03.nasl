#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(133056);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/01");

  script_cve_id(
    "CVE-2020-3710",
    "CVE-2020-3711",
    "CVE-2020-3712",
    "CVE-2020-3713",
    "CVE-2020-3714"
  );
  script_xref(name:"IAVA", value:"2020-A-0016-S");

  script_name(english:"Adobe Illustrator CC < 24.0.2 Multiple Vulnerabilites (APSB20-03)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator CC on the remote Windows hosts is prior to 24.0.2. It is, therefore, affected 
multiple memory corruption vulnerabilities which could lead to arbitrary code execution on the remote host. An 
unauthenticated, local attacker could exploit these issues to execute arbitrary commands on the host.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://helpx.adobe.com/security/products/illustrator/apsb20-03.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3864f93");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator CC 24.0.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");

  exit(0);
}

include('audit.inc');
include('install_func.inc');

appname = 'Adobe Illustrator';
product_info = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

version = product_info['version'];
path = product_info['path'];
fix = '24.0.2';

if(ver_compare(ver:version, fix:fix, strict:FALSE) != -1)
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

report = '\n  Path              : ' + path +
         '\n  Installed version : ' + version +
         '\n  Fix               : Update to version ' + fix + ' or later.' + '\n';

port = get_kb_item('SMB/transport');
if (!port)
  port = 445;
security_report_v4(severity: SECURITY_HOLE, port:port, extra:report);
