#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171510);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2023-21593");
  script_xref(name:"IAVA", value:"2023-A-0095");

  script_name(english:"Adobe InDesign < 17.4.1 / 18.0 < 18.2 Application denial-of-service (APSB23-12)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe InDesign instance installed on the remote host is affected by an application denial-of-service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior to 17.4.1, 18.2. It is, therefore, affected
by a vulnerability as referenced in the APSB23-12 advisory.

  - NULL Pointer Dereference (CWE-476) potentially leading to Application denial-of-service (CVE-2023-21593)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb23-12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 17.4.1, 18.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21593");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '17.4.1', 'fixed_display' : 'ID17.4.1' },
  { 'min_version' : '18.0', 'fixed_version' : '18.2', 'fixed_display' : 'ID18.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
