#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141343);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1236");
  script_bugtraq_id(99505);

  script_name(english:"IBM WebSphere MQ Denial of Service (CVE-2017-1236)");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM WebSphere MQ server 
installed on the remote Windows host is version 8.0.0.x prior to 8.0.0.7, 
9.0.x prior to 9.0.3 or 9.0.0.x prior to 9.0.0.2. It is, therefore, 
affected by a denial of service vulnerability. An authenticated, remote 
attacker can exploit this issue to cause the service to stop responding.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/docview.wss?uid=swg22003510");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.7 / 9.0.3 / 9.0.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1236");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('vcf.inc');

app = 'IBM WebSphere MQ';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

if( app_info['version'] =~ "^9\.0\.0\.\d{1,2}($|[^0-9])")
  constraints = [{ 'min_version' : '9.0.0.0', 'fixed_version' : '9.0.0.2'}];
else
  constraints = [
    { 'min_version' : '8.0.0', 'fixed_version' : '8.0.0.7'},
    { 'min_version' : '9.0.0', 'fixed_version' : '9.0.3'}
  ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
