#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151660);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-28591",
    "CVE-2021-28592",
    "CVE-2021-28593",
    "CVE-2021-36008",
    "CVE-2021-36009",
    "CVE-2021-36010",
    "CVE-2021-36011"
  );
  script_xref(name:"IAVA", value:"2021-A-0302-S");

  script_name(english:"Adobe Illustrator CC < 25.3 Multiple Vulnerabilities (APSB21-42)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Illustrator on the remote Windows hosts is prior to 25.3. It is, therefore, affected by
multiple vulnerabilities including the following:
  
  - Multiple critical out-of-bounds write vulnerabilities exist in Adobe Illustrator which could lead to 
    arbitrary code execution in the context of the current user. (CVE-2021-28591, CVE-2021-28592)

  - A use after free vulnerability exists in Adobe Illustrator. An unauthenticated, local attacker can exploit
    this to read arbitrary files on an affected system. (CVE-2021-28593)

  - An access of memory location after end of buffer vulnerability exists in Adobe Illustrator which could
    lead to  arbitrary code execution in the context of the current user. (CVE-2021-36009)

  - An out of bounds read vulnerability exists in Adobe Illustrator. An unauthenticated, local attacker can
    exploit this to read arbitrary files on an affected system. (CVE-2021-36010)

  - An OS command injection vulnerability exists in Adobe Illustrator which could lead to  arbitrary code
    execution in the context of the current user. (CVE-2021-36011)
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/illustrator/apsb21-42.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Illustrator CC 25.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36011");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_illustrator_installed.nasl");
  script_require_keys("SMB/Adobe Illustrator/Installed");

  exit(0);
}
include('vcf.inc');

var app_info = vcf::get_app_info(app:'Adobe Illustrator', win_local:TRUE);
var constraints = [{'fixed_version': '25.2.4', 'fixed_display': '25.3'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
