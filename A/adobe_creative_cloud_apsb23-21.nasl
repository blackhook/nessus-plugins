#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172541);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/24");

  script_cve_id("CVE-2023-26358");
  script_xref(name:"IAVA", value:"2023-A-0147");

  script_name(english:"Adobe Creative Cloud < 5.10.0 Arbitrary code execution (APSB23-21)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Creative Cloud instance installed on the remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud installed on the remote Windows host is prior to 5.10.0. It is, therefore, affected
by a vulnerability as referenced in the APSB23-21 advisory.

  - Untrusted Search Path (CWE-426) potentially leading to Arbitrary code execution (CVE-2023-26358)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb23-21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a634b80");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud version 5.10.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26358");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(426);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Creative Cloud", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Creative Cloud', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '5.10.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
