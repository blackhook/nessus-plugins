#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176066);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-2426");
  script_xref(name:"IAVB", value:"2023-B-0035-S");

  script_name(english:"Vim < 9.0.1499 DoS");

  script_set_attribute(attribute:"synopsis", value:
"A text editor installed on the remote Windows host is affected a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the version of Vim installed on the remote Windows host is prior to 9.0.1499. It is,
therefore affected by a denial of service vulnerability via an out-of-range pointer offset. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/vim/vim/commit/caf642c25de526229264cab9425e7c9979f3509b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c227fe66");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Vim version 9.0.1499 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2426");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vim:vim");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vim_win_installed.nbin");
  script_require_keys("installed_sw/Vim", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Vim', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '9.0.1499' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
