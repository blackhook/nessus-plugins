#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139326);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/07");

  script_cve_id("CVE-2020-4466");

  script_name(english:"IBM MQ 8.0.0.x < 8.0.0.15 / 8.1.0.x < 8.1.0.5 / 9.1.0.x < 9.1.0.5 LTS / 9.1.x < 9.1.5 CD Denial of Service (DoS) Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM MQ server installed on the remote host is 8.0.0.x prior to 8.0.0.15,
8.1.0.x prior to 8.1.0.5 with APAR IT28019, 9.1.0.x prior to 9.1.0.5, or 9.1.x prior to 9.1.5 and is therefore affected
 by a denial of service vulnerability. An authenticated, remote attacker can exploit this issue and cause a queue 
processing error crashing the affected host.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6252781");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6250473");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/181563");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.15, 8.1.0.5 with APAR IT28019, 9.1.0.5, 9.1.5, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);
app = 'IBM WebSphere MQ';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.0.15', 'fixed_display' : '8.0.0.15 with APAR IT28019' },
  { 'min_version' : '8.1.0', 'fixed_version' : '8.1.0.5'},
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.0.5'},
  { 'min_version' : '9.1.1', 'fixed_version' : '9.1.5', }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
