#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135693);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/03");

  script_cve_id("CVE-2020-3809");
  script_xref(name:"IAVA", value:"2020-A-0165-S");

  script_name(english:"Adobe After Effects <= 17.0.1 Information Disclosure (APSB20-21)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior or equal to 17.0.1. It is, therefore,
affected by an out-of-bounds read vulnerability. Successful exploitation could lead to an information disclosure.");
  # https://helpx.adobe.com/security/products/after_effects/apsb20-21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6756ec6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 17.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3809");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

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

# doing fixed of max_affected+1 here because the actual exe version we get
# is more granular. i.e. to cut off at 17.0.1 is to miss 17.0.1.123
constraints = [{ 'fixed_version' : '17.0.2', 'fixed_display' : '17.0.6' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
