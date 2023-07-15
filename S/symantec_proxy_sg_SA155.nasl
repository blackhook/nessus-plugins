#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105779);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2016-9099",
    "CVE-2016-9100",
    "CVE-2016-10256",
    "CVE-2016-10257"
  );
  script_bugtraq_id(
    102447,
    102451,
    102454,
    102455
  );

  script_name(english:"Symantec ProxySG 6.5 < 6.5.10.6 / 6.6 < 6.6.5.13 / 6.7 < 6.7.3.1 Multiple Vulnerabilities (SA155)");
  script_summary(english:"Checks the Symantec ProxySG SGOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The self-reported SGOS version installed on the remote Symantec
ProxySG device is 6.5.x prior to 6.5.10.6, 6.6.x prior to 6.6.5.13,
or 6.7 prior to 6.7.3.1. It is, therefore, affected by multiple
vulnerabilities :

  - A cross-site redirection attack due to improper validation of
    unspecified input in the web-based management console. A
    context-dependent attacker, with a specially crafted link, could
    redirect a user to a malicious site. (CVE-2016-9099)

  - An unspecified flaw within the management consoles. A remote
    attacker, with an authenticated admin user, could potentially
    obtain authentication credential information. (CVE-2016-9100)

  - Multiple cross-site scripting (XSS) attacks exist due to not
    validating unspecified input within the web-based management
    console. A context-dependent attacker, with a specially crafted
    request, could execute arbitrary script code.
    (CVE-2016-10256, CVE-2016-10257)

Note: At this time the is no fix for CVE-2016-9099, CVE-2016-10256,
and CVE-2016-10257 for Proxy SG 6.6.");
  # https://www.symantec.com/security-center/network-protection-security-advisories/SA155
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0136cdd9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec ProxySG SGOS version 6.5.10.6 / 6.6.5.13 / 6.7.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9099");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:symantec:proxysg");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

if (version !~ "^6\.([567])\.")
  audit(AUDIT_HOST_NOT, "Symantec ProxySG 6.5.x / 6.6.x / 6.7.x");

report_fix = NULL;

# Select version for report
if (isnull(ui_version)) report_ver = version;
else report_ver = ui_version;

if (version =~ "^6\.7\." && ver_compare(ver:version, fix:"6.7.3.1", strict:FALSE) == -1)
{
  fix    = '6.7.3.1';
  ui_fix = '6.7.3.1 Build 0';
}
else if (version =~ "^6\.6\." && ver_compare(ver:version, fix:"6.6.5.13", strict:FALSE) == -1)
{
  fix    = '6.6.5.13';
  ui_fix = '6.6.5.13 Build 0';
}
else if (version =~ "^6\.5\." && ver_compare(ver:version, fix:"6.5.10.6", strict:FALSE) == -1)
{
  fix    = '6.5.10.6';
  ui_fix = '6.5.10.6 Build 0';
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Symantec ProxySG', version);

# Select fixed version for report
if (isnull(ui_version)) report_fix = fix;
else report_fix = ui_fix;

report =
  '\n  Installed version : ' + report_ver +
  '\n  Fixed version     : ' + report_fix +
  '\n';

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report, xss:TRUE);
