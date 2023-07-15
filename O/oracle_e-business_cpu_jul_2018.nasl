#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111161);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-2934",
    "CVE-2018-2953",
    "CVE-2018-2988",
    "CVE-2018-2991",
    "CVE-2018-2993",
    "CVE-2018-2994",
    "CVE-2018-2995",
    "CVE-2018-2996",
    "CVE-2018-2997",
    "CVE-2018-3008",
    "CVE-2018-3012",
    "CVE-2018-3017",
    "CVE-2018-3018"
  );
  script_bugtraq_id(
    104831,
    104833,
    104835,
    104836,
    104837,
    104838,
    104840,
    104841
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (July 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the July 2018 Oracle Critical Patch Update (CPU). It is,
therefore, affected by multiple vulnerabilities as noted in the
July 2018 Critical Patch Update advisory :

  - An unspecified vulnerability in the Oracle One-to-One
    Fulfillment component of Oracle E-Business Suite
    in the Print Server subcomponent, which could allow
    an unauthenticated, remote attacker to compromise Oracle
    One-to-One Fulfillment. (CVE-2018-2953)

  - An unspecified vulnerability in the Oracle Order
    Management component of Oracle E-Business Suite in the
    Product Diagnostic Tools subcomponent which could allow
    a low privileged attacker to compromise Oracle Order
    Management. (CVE-2018-2954)

  - An unspecified vulnerability in Oracle Application
    Object Library component of Oracle E-Business Suite
    which could allow an unauthenticated, remote attacker
    to compromise Oracle Application Object Library.
    (CVE-2018-2934)

Additionally, Oracle E-Business is also affected by multiple additional
vulnerabilities in other components and subcomponents.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f36723");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2018 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2953");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Oracle/E-Business/Version");
patches = get_kb_item_or_exit("Oracle/E-Business/patches/installed");

# Batch checks
if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

p12_1 = '28018146';
p12_2 = '28018169';

# Check if the installed version is an affected version
affected_versions = make_array(
  '12.1.1', make_list(p12_1),
  '12.1.2', make_list(p12_1),
  '12.1.3', make_list(p12_1),

  '12.2.3', make_list(p12_2),
  '12.2.4', make_list(p12_2),
  '12.2.5', make_list(p12_2),
  '12.2.6', make_list(p12_2),
  '12.2.7', make_list(p12_2)
);

patched = FALSE;
affectedver = FALSE;

if (affected_versions[version])
{
  affectedver = TRUE;
  patchids = affected_versions[version];
  foreach required_patch (patchids)
  {
    foreach applied_patch (patches)
    {
      if(required_patch == applied_patch)
      {
        patched = applied_patch;
        break;
      }
    }
    if(patched) break;
  }
  if(!patched) patchreport = join(patchids,sep:" or ");
}

if (!patched && affectedver)
  {
  report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+version+' Patch '+patchreport+
      '\n';
    security_report_v4(port:0,extra:report,severity:SECURITY_WARNING);
  }
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
