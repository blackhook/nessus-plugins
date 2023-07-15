#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133357);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/07");

  script_cve_id("CVE-2019-4568");
  script_xref(name:"IAVA", value:"2020-A-0047-S");

  script_name(english:"IBM MQ 8.0.0.x < 8.0.0.14 / 9.0.0.x < 9.0.0.8 LTS Unspecified DoS (CVE-2019-4568)");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM MQ server installed on the
remote host is 8.0.0.x prior to 8.0.0.14 or 9.0..0.x prior to 9.0.0.8 LTS and
is therefore affected by a denial of service vulnerability. An unauthenticated,
remote attacker can exploit this issue, via an unspecified vector, to cause the
application to stop responding.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/1106517");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/166629");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.14, 9.0.0.8 LTS, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-4568");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}
include('vcf.inc');

app = 'IBM WebSphere MQ';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

if (app_info['Type'] != 'Server') audit(AUDIT_HOST_NOT,'affected');

constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.0.14' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.0.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
