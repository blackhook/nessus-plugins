##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164006);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-33640");
  script_xref(name:"IAVA", value:"2022-A-0324");

  script_name(english:"Security Updates for Microsoft Open Management Infrastructure (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Open Management Infrastructure server affected by an escalation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Open Management Infrastructure on the remote host is missing a security update. It is,
therefore, affected by the following vulnerability:

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2022-33640)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-33640
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d8e71ee");
  script_set_attribute(attribute:"see_also", value:"https://github.com/Microsoft/omi/releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Azure Open Management Infrastructure version 1.6.10.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:open_management_infrastructure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_omi_nix_installed.nbin");
  script_require_keys("installed_sw/omi");

  exit(0);
}

include('vcf.inc');

vcf::add_separator('-'); # used in parsing version for vcf
var app_info = vcf::combined_get_app_info(app:'omi');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '1.6.10.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
