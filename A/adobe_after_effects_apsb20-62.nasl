##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141834);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/13");

  script_cve_id("CVE-2020-24418", "CVE-2020-24419");
  script_xref(name:"IAVA", value:"2020-A-0489-S");

  script_name(english:"Adobe After Effects <= 17.1.1 Multiple Arbitrary Code Execution Vulnerabilities (APSB20-62)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior or equal to 17.1.1. It is, therefore,
affected by multiple vulnerabilities.

  - An out-of-bounds read vulnerability exists when parsing a crafted .aepx file, which could result in a read
    past the end of an allocated memory structure. An unauthenticated, local  attacker could exploit this to
    execute code in the context of the current user. This vulnerability requires user interaction to exploit.
    (CVE-2020-24418)

  - An uncontrolled search path vulnerability exists. An unauthenticated, local attacker can exploit this to
    to execute arbitrary code in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/after_effects/apsb20-62.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 17.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24418");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);

constraints = [
  { 'fixed_version' : '17.1.2', 'fixed_display' : '17.1.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
