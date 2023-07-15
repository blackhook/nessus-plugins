#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141848);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/22");

  script_cve_id("CVE-2020-24421");
  script_xref(name:"IAVA", value:"2020-A-0493-S");

  script_name(english:"Adobe InDesign <= 15.1.2 Arbitrary Code Execution Vulnerability (APSB20-66)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by Arbitrary Code Execution Vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote Windows host is prior or equal to 15.1.2. It is, therefore,
affected by an Arbitrary Code Execution vulnerability due to insecure handling of a malicious .indd file, potentially
resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this
vulnerability.");
  # https://helpx.adobe.com/security/products/indesign/apsb20-66.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60674b88");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 16.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24421");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:TRUE);

constraints = [
  { 'max_version':'15.1.2.226', 'fixed_version':'16.0.0.77' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
