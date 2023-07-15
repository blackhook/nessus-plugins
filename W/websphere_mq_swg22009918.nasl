#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129168);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/17 14:31:05");

  script_cve_id("CVE-2017-1612");
  script_bugtraq_id(102479);

  script_name(english:"IBM WebSphere MQ 7.0.1.x <= 7.0.1.14 / 7.1.0.x <= 7.1.0.8 / 7.5.0.x <= 7.5.0.8 / 8.0.0.x <= 8.0.0.7 / 9.0.0.x <= 9.0.0.1 / 9.0.1.x <= 9.0.3.0 Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM WebSphere MQ server installed on the remote host is
7.0.1.x <= 7.0.1.14, 7.1.0.x <= 7.1.0.8, 7.5.0.x <= 7.5.0.8, 8.0.0.x <= 8.0.0.7, 9.0.0.x <= 9.0.0.1, or
9.0.1.x <= 9.0.3.0 it is therefore affected by privilege escalation vulnerability. The service trace module
of IBM WebSphere MQ could be used to execute untrusted code under 'mqm' user.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22009918");
  script_set_attribute(attribute:"solution", value:
"Apply Fix Pack version 7.1.0.9 / 8.0.0.8 / 9.0.0.2 / 9.0.4.0 or install interim fix IT22526.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('http.inc');

# We can not detect Interim Fixes, so the check is Paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'IBM WebSphere MQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app, win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:4);

ifix = 'Interim Fix IT22526';
constraints = [
  {'min_version':'7.0.1.0', 'max_version':'7.0.1.14', 'fixed_display':ifix},
  {'min_version':'7.1.0.0', 'max_version':'7.1.0.8', 'fixed_display':'7.1.0.9 or ' + ifix},
  {'min_version':'7.5.0.0', 'max_version':'7.5.0.8', 'fixed_display':ifix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.7', 'fixed_display':'8.0.0.8 or ' + ifix},
  {'min_version':'9.0.0.0', 'max_version':'9.0.0.1', 'fixed_display':'9.0.0.2 or ' + ifix},
  {'min_version':'9.0.1.0', 'max_version':'9.0.3.0', 'fixed_display':'9.0.4.0 or ' + ifix}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
