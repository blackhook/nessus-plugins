#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149466);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2021-21101",
    "CVE-2021-21102",
    "CVE-2021-21103",
    "CVE-2021-21104",
    "CVE-2021-21105"
  );
  script_xref(name:"IAVA", value:"2021-A-0231-S");

  script_name(english:"Adobe Illustrator CC < 25.2.3 Multiple Vulnerabilities (APSB21-24)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator on the remote Windows hosts is prior to 25.2.3. It is, therefore, affected by
multiple vulnerabilities. 

  - A critical out-of-bounds write vulnerability that could lead to arbitrary code execution in the context
    of the current user. (CVE-2021-21101)
    
  - Multiple memory corruption vulnerablities that could lead to arbitrary code execution in the context of
    the current user. (CVE-2021-21103, CVE-2021-21104, CVE-2021-21105)
    
  - A path traversal write vulnerability that could lead to arbitrary code execution in the context of the
    current user. (CVE-2021-21102)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://helpx.adobe.com/security/products/illustrator/apsb21-24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?522b2559");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator CC 25.2.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21102");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Adobe Illustrator', win_local:TRUE);

var constraints = [{ 'fixed_version': '25.2.3' }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
