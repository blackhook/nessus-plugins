#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174982);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/02");

  script_cve_id("CVE-2023-24567", "CVE-2023-25544");
  script_xref(name:"IAVA", value:"2023-A-0271");

  script_name(english:"Dell EMC NetWorker Version Disclosure (DSA-2023-058)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by version disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell EMC NetWorker installed on the remote Windows host is 19.5 or earlier. It is, therefore, affected
by version disclosure vulnerabilities for 'Apache Tomcat' and 'RabbitMQ'. A NetWorker server user with remote access to
NetWorker clients can exploit this vulnerability to prepare target-specific attacks.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000210471/dsa-2023-058-dell-networker-security-update-for-version-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66246aa0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC NetWorker 19.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25544");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_networker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'EMC NetWorker', win_local:TRUE);

# CVEs only affect server components so audit if the server is not installed.
if (!app_info['Server'])
  vcf::audit(app_info);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '19.6' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
