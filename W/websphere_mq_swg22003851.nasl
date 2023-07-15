#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 6000 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(101838);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-1284", "CVE-2017-1285", "CVE-2017-1337");
  script_bugtraq_id(99493, 99494, 99538);

  script_name(english:"IBM WebSphere MQ 9.0.1 < 9.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM WebSphere MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM WebSphere MQ server
installed on the remote Windows host is 9.0.1 or 9.0.2 prior to 9.0.3.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to
    the insecure transmission of credentials in cleartext. A
    man-in-the-middle attacker can exploit this to disclose
    password information. Note that the software is only
    affected when PASSWORDPROTECTION=ALWAYS is set in
    mqclient.ini. (CVE-2017-1337)

  - An information disclosure vulnerability exists in
    WebSphere Application server traces when establishing
    CLIENT transport mode connections. A local attacker can
    exploit this to disclose sensitive information including
    passwords. (CVE-2017-1284)

  - A denial of service vulnerability exists due to improper
    handling of invalid messages. An authenticated, remote
    attacker can exploit this to cause an SDR or CLUSSDR
    channel to stop processing messages.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22003851");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22003853");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22003856");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WebSphere MQ version 9.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "IBM WebSphere MQ";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
version  = install['version'];
path     = install['path'];
fix      = NULL;

if(version =~ "9\.0\.[12]")
  fix = "9.0.3";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

# Check affected version
if(ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
