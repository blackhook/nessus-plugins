#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135237);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-2578", "CVE-2019-2579");

  script_name(english:"Oracle WebCenter Sites Multiple Vulnerabilities (April 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a remote security vulnerability.");
  script_set_attribute(attribute:"description", value:
"Oracle WebCenter Sites component of Oracle Fusion Middleware (subcomponent: Advanced UI) version 12.2.1.3.0 is
vulnerable to multiple vulnerabilities.

  - A vulnerability exists that could allow a remote attacker with network access over HTTP to to compromise
    Orable WebCenter Sites. This could result in the attacker gaining full access to all Oracle WebCenter
    Sites accessible data. (CVE-2019-2578)

  - A vulnerability exists that could allow a remote attacker with network access over HTTP and low privileges
    to compromise Orable WebCenter Sites. This could result in the attacker gaining unauthorized read access
    to a subset of Oracle WebCenter Sites. (CVE-2019-2579)");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2019.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2578");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_sites_installed.nbin");
  script_require_keys("SMB/WebCenter_Sites/Installed");

  exit(0);
}

port = get_kb_item('SMB/transport');
if (isnull(port))
  port = 445;

get_kb_item_or_exit('SMB/WebCenter_Sites/Installed');

versions = get_kb_list('SMB/WebCenter_Sites/*/Version');
if (isnull(versions)) exit(1, 'Unable to obtain a version list for Oracle WebCenter Sites.');

report = '';

foreach key (keys(versions))
{
  fix = '';

  version = versions[key];
  revision = get_kb_item(key - '/Version' + '/Revision');
  path = get_kb_item(key - '/Version' + '/Path');

  if (isnull(version) || isnull(revision)) continue;

  # Patch 29454018 - 12.2.1.3.0 < Revision 185640
  if (version =~ "^12\.2\.1\.3\.0$" && revision < 185640)
    fix = '\n  Fixed revision : 185640' +
          '\n  Required patch : 29454018';

  if (fix != '')
  {
    if (!isnull(path)) report += '\n  Path           : ' + path;
    report += '\n  Version        : ' + version +
              '\n  Revision       : ' + revision +
              fix + '\n';
  }
}

if (report != '') security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
else audit(AUDIT_INST_VER_NOT_VULN, "Oracle WebCenter Sites");
