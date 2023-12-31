#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88738);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-6004", "CVE-2015-6005", "CVE-2015-8261");
  script_bugtraq_id(79506, 80021);
  script_xref(name:"CERT", value:"176160");
  script_xref(name:"CERT", value:"753264");
  script_xref(name:"EDB-ID", value:"39231");

  script_name(english:"Ipswitch WhatsUp Gold < 16.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Ipswitch WhatsUp Gold.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Ipswitch
WhatsUp Gold running on the remote host is prior to 16.4.0. It is,
therefore, affected by the following vulnerabilities :

  - Multiple SQL injection vulnerabilities exist due to
    improper sanitization of user-supplied input to the 
    'sUniqueID' parameter and the 'find device' field. An
    authenticated, remote attacker can exploit this to
    inject or manipulate SQL queries in the back-end
    database, resulting in the manipulation or disclosure of
    arbitrary data. (CVE-2015-6004)

  - Multiple cross-site scripting vulnerabilities exist due
    to improper validation of user-supplied input to SNMP
    OID objects, SNMP trap messages, the View Names field,
    the Group Names field, the Flow Monitor Credentials
    field, the Flow Monitor Threshold Name field, the Task
    Library Name field, the Task Library Description field,
    the Policy Library Name field, the Policy Library
    Description field, the Template Library Name field, the
    Template Library Description field, the System Script
    Library Name field, the System Script Library
    Description field, and the CLI Settings Library
    Description field. An authenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2015-6005)

  - A SQL injection vulnerability exists due to improper
    validation of serialized XML objects in the
    DroneDeleteOldMeasurements SOAP request handler. A
    remote attacker can exploit this, via a crafted SOAP
    request, to inject or manipulate SQL queries in the
    back-end database, resulting in the manipulation or
    disclosure of arbitrary data. (CVE-2015-8261)");
  # https://docs.ipswitch.com/NM/64_WhatsUpGoldv164/01_ReleaseNotes/index.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?012ed7a2");
  # https://blog.rapid7.com/2015/12/16/multiple-disclosures-for-multiple-network-management-systems/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4df96cbb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch WhatsUp Gold version 16.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8261");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:whatsup_gold");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_whatsup_gold_detect.nbin");
  script_require_keys("installed_sw/Ipswitch WhatsUp Gold");
  script_require_ports("Services/www");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'Ipswitch WhatsUp Gold';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(
  app_name: appname,
  port: port,
  exit_if_unknown_ver: TRUE
);

version = install['version'];
if (version == 'unknown') audit(AUDIT_UNKNOWN_APP_VER, appname);

fix = '16.4.0.0';
fix_ui = '16.4.0';
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_ui +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
