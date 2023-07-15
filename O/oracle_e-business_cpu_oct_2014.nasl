#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78544);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2014-4278",
    "CVE-2014-4281",
    "CVE-2014-4285",
    "CVE-2014-6471",
    "CVE-2014-6472",
    "CVE-2014-6479",
    "CVE-2014-6523",
    "CVE-2014-6539",
    "CVE-2014-6550",
    "CVE-2014-6561"
  );
  script_bugtraq_id(
    70445,
    70447,
    70450,
    70454,
    70457,
    70461,
    70466,
    70471,
    70475,
    70485
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (October 2014 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the October 2014 Oracle Critical Patch Update (CPU). It is,
therefore, affected by vulnerabilities in the following components :

  - Oracle Application Technology Stack
  - Oracle Applications Framework
  - Oracle Applications Object Library
  - Oracle Payments");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ada40cc");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4278");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Oracle/E-Business/Version");
patches = get_kb_item_or_exit("Oracle/E-Business/patches/installed");

if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

# Check if the installed version is an affected version
affected_versions = make_array(
  '11.5.10.2' , make_list('19258563','19258561'),
  '12.0.4'    , make_list('19258575'),
  '12.0.6'    , make_list('19258575'),
  '12.1.1'    , make_list('19258579'),
  '12.1.2'    , make_list('19258579'),
  '12.1.3'    , make_list('19258579'),
  '12.2.2'    , make_list('19258581'),
  '12.2.3'    , make_list('19258581'),
  '12.2.4'    , make_list('19258581')
);

patched = FALSE;
affectedver = FALSE;

if (affected_versions[version])
{
  affectedver = TRUE;
  patchids = affected_versions[version];
  for (i=0; i < max_index(patchids); i++)
  {
    for (j=0; j < max_index(patches); j++)
    {
      if (patchids[i] == patches[j])
      {
        patched = patchids[i];
        break;
      }
      if (patched) break;
    }
  }
}

if (!patched && affectedver)
{
  security_hole(0);
  exit(0);
}
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
