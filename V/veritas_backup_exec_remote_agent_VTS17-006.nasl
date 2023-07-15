#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(101294);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/12");

  script_cve_id("CVE-2017-8895");
  script_bugtraq_id(98386);
  script_xref(name:"IAVA", value:"2017-A-0197-S");
  script_xref(name:"EDB-ID", value:"42282");

  script_name(english:"Veritas Backup Exec Remote Agent 14.1.x < 14.1.1786.1126 / 14.2.x < 14.2.1180.3160 / 16.0.x < 16.0.1142.1327 Use-after-free RCE (VTS17-006)");
  script_summary(english:"Checks the version of Veritas Backup Exec Remote Agent.");

  script_set_attribute(attribute:"synopsis", value:
"A remote data protection agent installed on the remote host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Vertias Backup Exec Remote Agent installed on the
remote Windows host is 14.1.x prior to 14.1.1786.1126, 14.2.x prior to
14.2.1180.3160, or 16.0.x prior to 16.0.1142.1327. It is, therefore,
affected by a remote code execution vulnerability due to a
use-after-free error that is triggered when creating SSL/TLS wrapped
NDMP sessions. An unauthenticated, remote attacker can exploit this to
cause a denial of service condition or the execution of arbitrary code
with SYSTEM level privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS17-006.html");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/May/93");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas Backup Exec Remote Agent version 14.1.1786.1126 /
14.2.1180.3160 / 16.0.1142.1327, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Veritas/Symantec Backup Exec SSL NDMP Connection Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:backup_exec_remote_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veritas_backup_exec_remote_agent_installed.nbin");
  script_require_keys("installed_sw/Veritas Backup Exec Remote Agent", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Veritas Backup Exec Remote Agent", win_local:TRUE);

constraints = [
  { "min_version" : "14.1", "fixed_version" : "14.1.1786.1126" },
  { "min_version" : "14.2", "fixed_version" : "14.2.1180.3160" },
  { "min_version" : "16.0", "fixed_version" : "16.0.1142.1327" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
