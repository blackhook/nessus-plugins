#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164632);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-34368");
  script_xref(name:"IAVA", value:"2022-A-0348-S");

  script_name(english:"Dell EMC NetWorker Privilege Escalation (DSA-2022-194)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell EMC NetWorker installed on the remote Windows host is 19.2.1.x, 19.3.x, 19.4.x 19.5.x 19.6.x
prior to 19.6.1.2 or 19.7.0.0. It is, therefore, affected by a privilege escalation vulnerability. An authenticated,
non-administrative attacker can exploit this vulnerability to gain access to restricted resources.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000201652/dsa-2022-194-dell-emc-networker-security-update-for-insufficient-privileges-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71b70b48");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC NetWorker 19.6.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_networker");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'EMC NetWorker', win_local:TRUE);

var constraints = [
  { 'min_version' : '19.2.1', 'max_version' : '19.2.1.99999999', 'fixed_display' : '19.6.1.2'},
  { 'min_version' : '19.3.0', 'fixed_version' : '19.6.1.2' },
  # A 19.7.0.1 has been released but this CVE is not in the patch notes so still send people to the advisory rather than
  # listing a fixed version.
  { 'equal': '19.7.0.0', 'fixed_display': 'See vendor advisory'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

