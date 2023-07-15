#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99479);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-3337",
    "CVE-2017-3393",
    "CVE-2017-3432",
    "CVE-2017-3515",
    "CVE-2017-3528",
    "CVE-2017-3549",
    "CVE-2017-3550",
    "CVE-2017-3555",
    "CVE-2017-3556",
    "CVE-2017-3557",
    "CVE-2017-3592"
  );
  script_bugtraq_id(
    97748,
    97757,
    97761,
    97764,
    97767,
    97770,
    97773,
    97777,
    97780,
    97783,
    97785
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (April 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the April 2017 Oracle Critical Patch Update (CPU). It is,
therefore, affected by the following vulnerabilities :

  - An unspecified flaw exists in the Oracle Marketing
    component within the User Interface subcomponent that
    allows an unauthenticated, remote attacker to impact
    confidentiality and integrity. This vulnerability only
    affects versions 12.1.1 through 12.1.3 and versions
    12.2.3 through 12.2.6. (CVE-2017-3337)

  - An unspecified flaw exists in the Oracle Advanced
    Outbound Telephony component within the Interaction
    History subcomponent that allows an unauthenticated,
    remote attacker to impact confidentiality and integrity.
    This vulnerability only affects versions 12.2.3 through
    12.2.6. (CVE-2017-3393)

  - An unspecified flaw exists in the Oracle One-to-One
    Fulfillment component within the Audience Workbench
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity. This
    vulnerability only affects versions 12.1.1 through
    12.1.3. (CVE-2017-3432)

  - An unspecified flaw exists in the Oracle User Management
    component within the User Name/Password Management
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity. This
    vulnerability only affects version 12.1.3 and versions
    12.2.3 through 12.2.6. (CVE-2017-3515)

  - An unspecified flaw exists in the Oracle Applications
    Framework component within the Popup windows lists
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity. This
    vulnerability only affects version 12.1.3 and versions
    12.2.3 through 12.2.6. (CVE-2017-3528)

  - An unspecified flaw exists in the Oracle Scripting
    component within the Scripting Administration
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity. This
    vulnerability only affects versions 12.1.1 through
    12.1.3 and versions 12.2.3 through 12.2.6.
    (CVE-2017-3549)

  - An unspecified flaw exists in the Oracle Customer
    Interaction History component within the Admin Console
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity. This
    vulnerability only affects versions 12.1.1 through
    12.1.3. (CVE-2017-3550)

  - An unspecified flaw exists in the Oracle iReceivables
    component within the Self Registration subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. This vulnerability only
    affects versions 12.1.1 through 12.1.3 and versions
    12.2.3 through 12.2.6. (CVE-2017-3555)

  - An unspecified flaw exists in the Oracle Application
    Object Library component within the File Management
    subcomponent that allows an unauthenticated, remote
    attacker to disclose potentially sensitive information.
    This vulnerability only affects version 12.1.3 and
    versions 12.2.3 through 12.2.6. (CVE-2017-3556)

  - An unspecified flaw exists in the Oracle One-to-One
    Fulfillment component within the Print Server
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity. This
    vulnerability only affects version 12.1.3 and versions
    12.2.3 through 12.2.6. (CVE-2017-3557)

  - An unspecified flaw exists in the Oracle Payables
    component within the Self Service Manager subcomponent
    that allows an authenticated, remote attacker to impact
    confidentiality and integrity. This vulnerability only
    affects versions 12.1.1 through 12.1.3 and versions
    12.2.3 through 12.2.6. (CVE-2017-3592)");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixEBS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?620f75f9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3592");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

p12_1 = '25449171';
p12_2 = '25449173';

# Check if the installed version is an affected version
affected_versions = make_array(
  '12.1.1', make_list(p12_1),
  '12.1.2', make_list(p12_1),
  '12.1.3', make_list(p12_1),

  '12.2.3', make_list(p12_2),
  '12.2.4', make_list(p12_2),
  '12.2.5', make_list(p12_2),
  '12.2.6', make_list(p12_2)
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
  if(report_verbosity > 0)
  {
    report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+version+' Patch '+patchreport+
      '\n';
    security_hole(port:0,extra:report);
  }
  else security_hole(0);
  exit(0);
}
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
