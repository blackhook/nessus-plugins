#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140187);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-4376");
  script_xref(name:"IAVA", value:"2020-A-0383-S");

  script_name(english:"IBM MQ 8.0 < 8.0.0.15 / 8.1 < 8.1.0.5 HPE/ 9.1 < 9.1.0.5 LTS / 9.1 < 9.2 CD DoS");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM MQ server installed on the remote host is 8.0.0.x prior to 8.0.0.15,
8.1.x prior to 8.1.0.5, 9.0.x prior to 9.0.0.10, 9.1.0.x prior to 9.1.0.5, or 9.1.x prior to 9.2 and it is therefore 
affected by a denial of service (DoS) vulnerability. An authenticated, remote attacker can exploit this using an issue 
within the pubsub messaging logic");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6252779");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/179081");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6242364");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/179081");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.15, 8.1.0.5 HPE, 9.1.0.5, 9.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4376");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl", "ibm_mq_detect.nbin");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('vcf.inc');

app = 'IBM WebSphere MQ';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

if (app_info['Type'] != 'Server') audit(AUDIT_HOST_NOT,'affected');

constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.0.15'},
  { 'min_version' : '8.1.0', 'fixed_version' : '8.1.0.5'}, #HPE fix.
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.0.5'},
  { 'min_version' : '9.1.1', 'fixed_version' : '9.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
