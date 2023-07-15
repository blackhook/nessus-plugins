#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59427);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2012-2034",
    "CVE-2012-2035",
    "CVE-2012-2036",
    "CVE-2012-2037",
    "CVE-2012-2038",
    "CVE-2012-2039"
  );
  script_bugtraq_id(53887);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"Adobe AIR for Mac 3.x <= 3.2.0.2070 Multiple Vulnerabilities (APSB12-14)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a version of Adobe AIR that is
affected by multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Adobe AIR on the remote
Mac OS X host is 3.2.0.2070 or earlier and is reportedly affected by
multiple vulnerabilities :

  - Multiple memory corruption vulnerabilities exist that 
    could lead to code execution. (CVE-2012-2034, 
    CVE-2012-2037)

  - A stack overflow vulnerability exists that could lead to
    code execution. (CVE-2012-2035)

  - An integer overflow vulnerability exists that could lead
    to code execution. (CVE-2012-2036)

  - A security bypass vulnerability exists that could lead 
    to information disclosure. (CVE-2012-2038)

  - A null dereference vulnerability exists that could lead
    to code execution. (CVE-2012-2039)");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR 3.3 (3.3.0.3610) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2039");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_air_installed.nasl");
  script_require_keys("MacOSX/Adobe_AIR/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Adobe_AIR";
version = get_kb_item_or_exit(kb_base+"/Version");
path = get_kb_item_or_exit(kb_base+"/Path");

# nb: we're checking for versions less than *or equal to* the cutoff!
cutoff_version = '3.2.0.2070';
fixed_version_for_report = '3.3.0.3610';

if (version =~ '^3\\.' && ver_compare(ver:version, fix:cutoff_version, strict:FALSE) <= 0)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version_for_report+'\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version, path);
