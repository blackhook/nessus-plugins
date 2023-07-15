#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136998);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-7501",
    "CVE-2016-0714",
    "CVE-2017-3540",
    "CVE-2017-3541",
    "CVE-2017-3542",
    "CVE-2017-3543",
    "CVE-2017-3545",
    "CVE-2017-3554",
    "CVE-2017-3591",
    "CVE-2017-3593",
    "CVE-2017-3594",
    "CVE-2017-3595",
    "CVE-2017-3596",
    "CVE-2017-3597",
    "CVE-2017-3598",
    "CVE-2017-3602",
    "CVE-2017-3603",
    "CVE-2017-5638"
  );
  script_xref(name:"IAVA", value:"2017-A-0113-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Oracle WebCenter Sites Multiple Vulnerabilities (April 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Oracle WebCenter Sites component of Oracle Fusion Middleware is vulnerable to multiple vulnerabilities.

  - A remote code execution in the Oracle WebCenter Sites component of Oracle Fusion Middleware (subcomponent:
    Install (Apache Common Collections)). An unauthenticated, remote attacker can exploit this, via a crafted
    serialized Java object, to bypass authentication and execute arbitrary commands. (CVE-2015-7501)

  - An unspecified vulnerability in the Oracle WebCenter Sites component of Oracle Fusion Middleware
    (subcomponent: Server). An unauthenticated, remote attacker can exploit this, via HTTP, to obtain access
    to critical data or complete access to all Oracle WebCenter Sites accessible data as well as unauthorized
    update, insert or delete access to some of Oracle WebCenter Sites accessible data and unauthorized ability
    to cause a partial denial of service (partial DOS) of Oracle WebCenter Sites. (CVE-2017-3542)

  - A remote code execution in the Oracle WebCenter Sites component of Oracle Fusion Middleware (subcomponent:
    Third Party Tools (Struts 2)) due to incorrect exception handling and error-message generation during
    file-upload attempts. An unauthenticated, remote attacker can exploit this, via a crafted Content-Type,
    Content-Disposition, or Content-Length HTTP header, to bypass authentication and execute arbitrary
    commands. (CVE-2017-5638)

In addition, Oracle WebCenter Sites is also affected by several additional vulnerabilities including code execution,
denial of service, information disclosure, and other unspecified vulnerabilities. Note that Nessus has not attempted to
exploit these issues but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2017.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5638");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts Jakarta Multipart Parser OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

  # Patch 25883419 - 11.1.1.8.0 < Revision 184000 
  if (version =~ "^11\.1\.1\.8\.0$" && revision < 184000)
  {
    fix = '\n  Fixed revision : 184000' +
          '\n  Required patch : 25883419';
  }
  # Patch 25806935 - 12.2.1.0.0 < Revision 184040 
  else if (version =~ "^12\.2\.1\.0\.0$" && revision < 184040)
  {
    fix = '\n  Fixed revision : 184040' +
          '\n  Required patch : 25806935';
  }
  # Patch 25806943 - 12.2.1.1.0 < Revision 184025 
  else if (version =~ "^12\.2\.1\.1\.0$" && revision < 184025)
  {
    fix = '\n  Fixed revision : 184025' +
          '\n  Required patch : 25806943';
  }
  # Patch 25806946 - 12.2.1.2.0 < Revision 184026 
  else if (version =~ "^12\.2\.1\.2\.0$" && revision < 184026)
  {
    fix = '\n  Fixed revision : 184026' +
          '\n  Required patch : 25806946';
  }

  if (fix != '')
  {
    if (!isnull(path)) report += '\n  Path           : ' + path;
    report += '\n  Version        : ' + version +
              '\n  Revision       : ' + revision +
              fix + '\n';
  }
}

if (report != '') security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
else audit(AUDIT_INST_VER_NOT_VULN, "Oracle WebCenter Sites");

