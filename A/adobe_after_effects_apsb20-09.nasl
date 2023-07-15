#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134168);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/19");

  script_cve_id("CVE-2020-3765");
  script_xref(name:"IAVA", value:"2020-A-0082-S");

  script_name(english:"Adobe After Effects <= 16.1.2 Arbitrary Code Execution (APSB20-09)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by Arbitrary Code Execution Vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior or equal to 16.1.2. It is, therefore,
affected by an out-of-bounds write vulnerability. Successful exploitation could lead to arbitrary code execution.");
  # https://helpx.adobe.com/security/products/after_effects/apsb20-09.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?151d5f37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 17.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3765");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);

constraints = [{ 'fixed_version' : '16.1.3', 'fixed_display' : '17.0.4' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
