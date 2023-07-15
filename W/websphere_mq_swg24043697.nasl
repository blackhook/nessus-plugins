#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123510);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/30 13:24:47");

  script_cve_id("CVE-2018-1836");

  script_name(english:"IBM MQ 9.0.2 - 9.0.5 / 9.1.0.x < 9.1.0.1 Console Cross Site Scripting (XSS) Vulnerability (CVE-2018-1836)");
  script_summary(english:"Checks the version of IBM MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected
by a cross site scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM MQ server installed
on the remote host is 9.0.2 CD - 9.05 CD, or 9.1.0.x LTS < 9.1.0.1
LTS, and is therefore affected by a cross site scripting (XSS)
vulnerability in the IBM MQ Web Console due to improper validation of
user-supplied input before returning it to users. An unauthenticated,
remote attacker can exploit this, by convincing a user to click a
specially crafted URL, to execute arbitrary script code in a user's
browser session.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=ibm10734457");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg24043697");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 9.1.1 or apply interim fix for APAR IT26555 to IBM
MQ 9.1.0.1 as per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1836");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'IBM WebSphere MQ';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '9.0.2', 'max_version' : '9.0.5', 'fixed_version' : '9.1.1'},
  { 'min_version' : '9.1', 'fixed_version' : '9.1.0.2', 'fixed_display' : '9.1.0.2 or 9.1.0.1 with APAR IT26555' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:TRUE});
