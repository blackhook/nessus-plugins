#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108713);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-1218");

  script_name(english:"EMC NetWorker < 8.2.4.11 / 9.x < 9.1.1.6 / 9.2.x < 9.2.1.1");
  script_summary(english:"Checks the version of EMC NetWorker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC NetWorker installed on the remote Windows host is
prior to 8.2.4.11 or 9.x prior to 9.1.1.6 or 9.2.x prior to
9.2.1.1. It is, therefore, affected by a buffer overflow
vulnerability. A remote, unauthenticated attacker may potentially
exploit this vulnerability to cause a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2018/Mar/43");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC NetWorker 8.2.4.11 / 9.1.1.6 / 9.2.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1218");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker");
  script_require_ports(139, 445);

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::get_app_info(app:"EMC NetWorker", win_local:TRUE);

if(app_info['Server'] != 1) audit(AUDIT_INST_VER_NOT_VULN, "EMC NetWorker Client");

constraints = [
  { "min_version" : "0.0",   "max_version" : "8.2.4.10", "fixed_version" : "8.2.4.11" },
  { "min_version" : "9.0",   "max_version" : "9.1.1.5",  "fixed_version" : "9.1.1.6" },
  { "min_version" : "9.2.0", "max_version" : "9.2.1.0",  "fixed_version" : "9.2.1.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
