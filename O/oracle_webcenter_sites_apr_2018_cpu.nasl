#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109209);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2016-3092", "CVE-2017-12617", "CVE-2018-2791");
  script_bugtraq_id(91453, 100954, 103800);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Oracle WebCenter Sites Remote Vulnerability (April 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a remote security vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Sites running on the remote host is affected by an unspecified flaw in the Sites
component (formerly FatWire Content Server) that allows an remote attacker to impact confidentiality and integrity.
Note that this issue only applies to versions 11.1.1.8.0, 12.2.1.2.0,and 12.2.1.3.0.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e39ef65");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2018 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12617");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2791");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  # Patch 27589552 - 11.1.1.8.0 < Revision 184362 
  if (version =~ "^11\.1\.1\.8\.0$" && revision < 184362)
    fix = '\n  Fixed revision : 184362' +
          '\n  Required patch : 27589552';

  # Patch 27589545 - 12.2.1.2.0 < Revision 184799
  else if (version =~ "^12\.2\.1\.2\.0$" && revision < 184799)
    fix = '\n  Fixed revision : 184799' +
          '\n  Required patch : 27589545';

  # Patch 27562268 - 12.2.1.3.0 < Revision 184667
  else if (version =~ "^12\.2\.1\.3\.0$" && revision < 184667)
    fix = '\n  Fixed revision : 184667' +
          '\n  Required patch : 27562268';

  if (fix != '')
  {
    if (!isnull(path)) report += '\n  Path           : ' + path;
    report += '\n  Version        : ' + version +
              '\n  Revision       : ' + revision +
              fix + '\n';
  }
}

if (report != '') security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
else audit(AUDIT_INST_VER_NOT_VULN, 'Oracle WebCenter Sites');
