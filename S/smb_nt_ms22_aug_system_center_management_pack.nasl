##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164007);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-33640");
  script_xref(name:"IAVA", value:"2022-A-0324");

  script_name(english:"Security Updates for Microsoft System Center Management Pack (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"A data center management system component on the remote Windows system is affected by an escalation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft System Center Management Pack for UNIX/Linux on the remote host is missing a security update. It is,
therefore, affected by the following vulnerability:

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2022-33640)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-33640
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d8e71ee");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the System Center Management Pack for UNIX/Linux 2016, 2019, and 2022.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("system_center_management_pack_installed.nbin");
  script_require_ports("installed_sw/System Center Management Pack for UNIX and Linux");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'System Center Management Pack for UNIX and Linux', win_local:TRUE);

var constraints = [
  { 'min_version':'7.2.0.0',    'fixed_version':'7.6.1113.0' },   # 2016
  { 'min_version':'10.19.0.0',  'fixed_version':'10.19.1158.0' }, # 2019
  { 'min_version':'10.22.0.0',  'fixed_version':'10.22.1032.0' }  # 2022
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
