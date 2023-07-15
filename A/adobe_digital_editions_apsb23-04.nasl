#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174126);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id("CVE-2023-21582");
  script_xref(name:"IAVA", value:"2023-A-0197");

  script_name(english:"Adobe Digital Editions < 4.5.11.187658 Arbitrary code execution (APSB23-04)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Digital Editions instance installed on the remote host is affected by an arbitrary code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote Windows host is prior to 4.5.11.187658. It is, therefore,
affected by a vulnerability as referenced in the APSB23-04 advisory.

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2023-21582)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb23-04.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37346d6f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.11.187658 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21582");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_digital_editions_installed.nbin");
  script_require_keys("installed_sw/Adobe Digital Editions", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Digital Editions', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '4.5.11.187658' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
