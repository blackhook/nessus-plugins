#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111333);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id(
    "CVE-2017-3738",
    "CVE-2018-0733",
    "CVE-2018-0739",
    "CVE-2018-1304",
    "CVE-2018-1305",
    "CVE-2018-1000120",
    "CVE-2018-1000121",
    "CVE-2018-1000122",
    "CVE-2018-1000300",
    "CVE-2018-1000301"
  );
  script_bugtraq_id(
    102118,
    103144,
    103170,
    103414,
    103415,
    103436,
    103517,
    103518,
    104207,
    104225
  );

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (July 2018 CPU)");
  script_summary(english:"Checks the version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Secure Global Desktop installed on the remote
host is 5.3 / 5.4 and is missing a security patch from the July 2018
Critical Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities:

 - curl version curl 7.54.1 to and including curl 7.59.0 contains a 
 Heap-based Buffer Overflow vulnerability in FTP connection closing
 down functionality which can lead to DoS and RCE conditions. This 
 vulnerability appears to have been fixed in curl < 7.54.1 and 
 curl >= 7.60.0. (CVE-2018-1000300)

 - Security constraints defined by annotations of Servlets in Apache 
 Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and 
 7.0.0 to 7.0.84 were only applied once a Servlet had been loaded. 
 It was possible - depending on the order Servlets were loaded - for 
 some security constraints not to be applied. This could have exposed 
 resources to unauthorized users. (CVE-2018-1305)

 - ASN.1 types with a recursive definition could exceed the stack 
 given malicious input with excessive recursion. This could result 
 in a Denial Of Service attack. Fixed in OpenSSL 1.1.0h (Affected 
 1.1.0-1.1.0g). Fixed in OpenSSL 1.0.2o (Affected 1.0.2b-1.0.2n).
 (CVE-2018-0739)");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4c9a415");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

app = 'Oracle Secure Global Desktop';
version = get_kb_item_or_exit('Host/Oracle_Secure_Global_Desktop/Version');

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit('Host/uname');
if ('Linux' >!< uname) audit(AUDIT_OS_NOT, 'Linux');

fix_required = NULL;

if (version =~ "^5\.30($|\.)")
  fix_required = make_list('Patch_53p5');
else if (version =~ "^5\.40($|\.)")
  fix_required = make_list('Patch_54p1', 'Patch_54p2', 'Patch_54p3');

if (isnull(fix_required)) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle Secure Global Desktop', version);

patches = get_kb_list('Host/Oracle_Secure_Global_Desktop/Patches');

patched = FALSE;
foreach patch (patches)
{
  foreach fix (fix_required)
  {
    if (patch == fix)
    {
      patched = TRUE;
      break;
    }
  }
  if (patched) break;
}

if (patched) audit(AUDIT_INST_VER_NOT_VULN, app, version + ' (with ' + patch + ')');


report = '\n  Installed version : ' + version +
         '\n  Patch required    : ' + fix_required[0] +
         '\n';
security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
