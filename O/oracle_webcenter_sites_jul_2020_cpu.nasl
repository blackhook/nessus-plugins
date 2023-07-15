#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138590);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-14613");
  script_xref(name:"IAVA", value:"2020-A-0327-S");

  script_name(english:"Oracle WebCenter Sites (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"Oracle WebCenter Sites component of Oracle Fusion Middleware is affected by a vulnerability in the Oracle WebCenter 
Sites product of Oracle Fusion Middleware (component: Advanced User Interface). Supported versions that are affected 
are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access 
via HTTP to compromise Oracle WebCenter Sites. Successful attacks require human interaction from a person other than 
the attacker and while the vulnerability is in Oracle WebCenter Sites, attacks may significantly impact additional 
products. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some 
of Oracle WebCenter Sites accessible data as well as unauthorized read access to a subset of Oracle WebCenter Sites 
accessible data.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  # https://www.oracle.com/security-alerts/cpujul2020.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc7b9bd1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_sites_installed.nbin", "oracle_enum_products_win.nbin");
  script_require_keys("SMB/WebCenter_Sites/Installed");

  exit(0);
}

include('oracle_rdbms_cpu_func.inc');

port = get_kb_item('SMB/transport');
if (isnull(port))
  port = 445;

get_kb_item_or_exit('SMB/WebCenter_Sites/Installed');

versions = get_kb_list('SMB/WebCenter_Sites/*/Version');
if (isnull(versions))
  exit(1, 'Unable to obtain a version list for Oracle WebCenter Sites.');

report = '';

foreach key (keys(versions))
{
  fix = '';

  version = versions[key];
  revision = get_kb_item(key - '/Version' + '/Revision');
  path = get_kb_item(key - '/Version' + '/Path');

  if (isnull(version) || isnull(revision))
    continue;

  if (version =~ "^12\.2\.1\.3\.0$" && revision < 186084)
  {
    fix = '\n  Fixed revision : 186084' +
          '\n  Required patch : 31548911';
  }
  else if (version =~ "^12\.2\.1\.4\.0$" && revision < 186094)
  {
    fix = '\n  Fixed revision : 186094' +
          '\n  Required patch : 31548912';
  }

  if (fix != '')
  {
    if (!isnull(path)) 
      report += '\n  Path           : ' + path;

    report += '\n  Version        : ' + version +
              '\n  Revision       : ' + revision +
              fix + '\n';
  }
}

if (empty_or_null(report))
  audit(AUDIT_INST_VER_NOT_VULN, 'Oracle WebCenter Sites');

security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
