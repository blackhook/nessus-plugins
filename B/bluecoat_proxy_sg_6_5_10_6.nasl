#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104381);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2016-9097");
  script_bugtraq_id(101530);

  script_name(english:"Symantec (Blue Coat) ProxySG 6.5.x < 6.5.10.6 / 6.6.x < 6.6.5.8 / 6.7.x < 6.7.1.2 Impromper User Authorization Vulnerability");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The self-reported version of the remote Symantec (Blue Coat) ProxySG
device is 6.5.x prior to 6.5.10.6, 6.6.x prior to 6.6.5.8, or 6.7.x
prior to 6.7.1.2. It is, therefore, affected by an improper user
authorization vulnerability in web-based management console.");
  # https://www.symantec.com/security-center/network-protection-security-advisories/SA146
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0320c5d9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.5.10.6 / 6.6.5.8 / 6.7.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

if(version !~ "^6\.([765])\.")
  audit(AUDIT_HOST_NOT, "Blue Coat ProxySG 6.7.x / 6.6.x / 6.5.x");

report_fix = NULL;

# Select version for report
if (isnull(ui_version)) report_ver = version;
else report_ver = ui_version;

if(version =~ "^6\.5\." && ver_compare(ver:version, fix:"6.5.10.6", strict:FALSE) == -1)
{
  fix    = '6.5.10.6';
  ui_fix = '6.5.10.6 Build 0';
}
else if(version =~ "^6\.6\." && ver_compare(ver:version, fix:"6.6.5.8", strict:FALSE) == -1)
{
  fix    = '6.6.5.8';
  ui_fix = '6.6.5.8 Build 0';
}
else if(version =~ "^6\.7\." && ver_compare(ver:version,fix:"6.7.1.2",strict:FALSE) == -1)
{
  fix    = '6.7.1.2';
  ui_fix = '6.7.1.2 Build 0';
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Blue Coat ProxySG', version);

# Select fixed version for report
if (isnull(ui_version)) report_fix = fix;
else report_fix = ui_fix;

report =
  '\n  Installed version : ' + report_ver +
  '\n  Fixed version     : ' + report_fix +
  '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
