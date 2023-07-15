#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104051);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-10033");
  script_bugtraq_id(101408);

  script_name(english:"Oracle WebCenter Sites Local Vulnerability (Oct 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a local security vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Sites running on the remote host is affected by an unspecified flaw in the Sites
component (formerly FatWire Content Server) that allows an authenticated, local attacker to impact confidentiality and
integrity. Note that this issue only applies to versions 11.1.1.8.0 and 12.2.1.2.0.");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b680917f");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oct 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10033");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  # Patch 25883419 - 11.1.1.8.0 < Revision 184000 
  if (version =~ "^11\.1\.1\.8\.0$" && revision < 184000)
    fix = '\n  Fixed revision : 184000' +
          '\n  Required patch : 25883419';

  # Patch 25806946 - 12.2.1.2.0 < Revision 184026
  else if (version =~ "^12\.2\.1\.2\.0$" && revision < 184026)
    fix = '\n  Fixed revision : 184026' +
          '\n  Required patch : 25806946';

  if (fix != '')
  {
    if (!isnull(path)) report += '\n  Path           : ' + path;
    report += '\n  Version        : ' + version +
              '\n  Revision       : ' + revision +
              fix + '\n';
  }
}

if (report != '') security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
else audit(AUDIT_INST_VER_NOT_VULN, 'Oracle WebCenter Sites');

