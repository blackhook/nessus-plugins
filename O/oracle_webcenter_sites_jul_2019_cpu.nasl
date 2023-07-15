#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136091);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2016-6814",
    "CVE-2016-1000031",
    "CVE-2018-8013",
    "CVE-2018-15756"
  );
  script_xref(name:"IAVA", value:"2019-A-0256-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle WebCenter Sites Multiple Vulnerabilities (July 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Oracle WebCenter Sites component of Oracle Fusion Middleware is vulnerable to multiple vulnerabilities :

  - A deserialization vulnerability exists in the Oracle WebCenter Sites component of Oracle Fusion Middleware
    (subcomponent: Advanced UI (Apache Groovy)) due to a lack of isolation of object deserialization code. An
    unauthenticated, remote attacker can exploit this, via HTTP, to execute arbitrary code on the target host.
    (CVE-2016-6814)

  - A remote code execution vulnerability exists in the Oracle WebCenter Sites component of Oracle Fusion
    Middleware (subcomponent: Advanced UI (Apache Commons FileUpload)) due to an unspecified reason. An
    unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary commands.
    (CVE-2016-1000031)

  - A denial of service (DoS) vulnerability exists in the Oracle WebCenter Sites component of Oracle Fusion
    Middleware (subcomponent: Third Party Tools (Apache Batik)) due to an issue with deserialization. An
    unauthenticated, remote attacker can exploit this issue, via HTTP, to cause the application to stop
    functioning properly. (CVE-2018-8013)

  - A denial of service (DoS) vulnerability exists in the Oracle WebCenter Sites component of Oracle Fusion
    Middleware (subcomponent: Advanced UI (Spring Framework)) due to an issue handling range requests with
    a high number of ranges, wide ranges that overlap, or both. An unauthenticated, remote attacker can
    exploit this issue, via HTTP, to cause the application to stop responding. (CVE-2018-15765)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2019.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1000031");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

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

get_kb_item_or_exit('SMB/WebCenter_Sites/Installed');

port = get_kb_item('SMB/transport');
if (isnull(port))
  port = 445;

versions = get_kb_list('SMB/WebCenter_Sites/*/Version');
if (isnull(versions)) exit(1, 'Unable to obtain a version list for Oracle WebCenter Sites.');

report = '';

# vulnerable versions: 
# - 12.2.1.3.0 - Revision 185862, Patch 29957990
#     Note that the revision does not match up with the version suffix shown in the readme

foreach key (keys(versions))
{
  fix = '';

  version = versions[key];
  revision = get_kb_item(key - '/Version' + '/Revision');
  path = get_kb_item(key - '/Version' + '/Path');

  if (isnull(version) || isnull(revision)) continue;

  # Patch 29957990 - 12.2.1.3.0 < Revision 185862
  if (version =~ "^12\.2\.1\.3\.0$" && revision < 185862)
  {
    fix = '\n  Fixed revision : 185862' +
          '\n  Required patch : 29957990';
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
