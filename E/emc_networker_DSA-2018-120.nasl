#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(111528);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id("CVE-2018-11050");
  script_xref(name:"IAVA", value:"2018-A-0243-S");

  script_name(english:"EMC NetWorker Server 9.x < 9.1.1.9 / 9.2.x < 9.2.1.4 / 18.1.0.1");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a Clear-Text authentication over network vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC NetWorker Server installed on the remote Windows host is
9.x prior to 9.1.1.9 or 9.2.x prior to 9.2.1.4 or 18.1.0.1. It is, 
therefore, affected by a Clear-Text authentication over network 
vulnerability. An unauthenticated attacker in the same network could 
potentially exploit this vulnerability to access the component with 
the credentials of an authenticated user.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2018/Jul/92");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC NetWorker 9.1.1.9 / 9.2.1.4 / 18.1.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11050");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");
  script_require_ports(139, 445);

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"EMC NetWorker", win_local:TRUE);
if (!app_info['Server'])
  exit(0,
      'EMC NetWorker Client version ' + app_info['version'] +
      ' installed and not vulnerable. Only Server installs' +
      ' are vulnerable.');

constraints = [
  { "min_version" : "9.0",      "fixed_version" : "9.1.1.9" },
  { "min_version" : "9.2.0",    "fixed_version" : "9.2.1.4" },
  { "min_version" : "18.1.0.1", "fixed_version" : "18.1.0.2" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
