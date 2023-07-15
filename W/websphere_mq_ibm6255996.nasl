#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139730);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-4465");
  script_xref(name:"IAVA", value:"2020-A-0383-S");

  script_name(english:"IBM MQ 7.1 / 7.5 / 8.0 < 8.0.0.15 / 9.0 < 9.0.0.10 LTS / 9.1 < 9.1.0.6 LTS / 9.1 < 9.1.5 CD DoS");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM MQ server installed on the remote host is 7.1, 7.5, 8.0.0.x prior to
8.0.0.15, 9.0.x prior to 9.0.0.10, 9.1.0.x prior to 9.1.0.6, or 9.1.x prior to 9.1.5 and it is therefore affected by a
denial of service (DoS) vulnerability. An authenticated, remote attacker can exploit this issue by overflowing a buffer
in the channel processing code using an older client in order to crash the system.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6255996");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/181562");
  script_set_attribute(attribute:"solution", value:
"Install fix for APAR IT32141 or upgrade to IBM MQ 8.0.0.15, 9.0.0.10, 9.1.0.6, 9.1.5, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);
app = 'IBM WebSphere MQ';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

fix = 'Contact IBM Support and request a fix for APAR IT32141';

constraints = [
  { 'min_version' : '7.1',   'fixed_version' : '7.2', 'fixed_display' : fix },
  { 'min_version' : '7.5',   'fixed_version' : '7.6', 'fixed_display' : fix },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.0.15'},
  { 'min_version' : '9.0',   'fixed_version' : '9.0.0.10'},
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.0.6'},
  { 'min_version' : '9.1.1', 'fixed_version' : '9.1.5', }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

