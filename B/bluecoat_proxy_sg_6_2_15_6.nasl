#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76164);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Blue Coat ProxySG 6.2.x OpenSSL Security Bypass");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is potentially affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Blue Coat ProxySG device's SGOS self-reported version is
6.2 prior to 6.2.15.6. It, therefore, contains a bundled version of
OpenSSL that has multiple flaws, meaning it is potentially affected by
an unspecified error that could allow an attacker to cause usage of
weak keying material leading to simplified man-in-the-middle attacks.");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa80");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.2.15.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

if (version !~ "^6\.2\.") audit(AUDIT_HOST_NOT, "Blue Coat ProxySG 6.2.x");

report_fix = NULL;

# Select version for report
if (isnull(ui_version)) report_ver = version;
else report_ver = ui_version;

if (version =~ "^6\.2\." && ver_compare(ver:version, fix:"6.2.15.6", strict:FALSE) == -1)
{
  fix    = '6.2.15.6';
  ui_fix = '6.2.15.6 Build 0';

  # Select fixed version for report
  if (isnull(ui_version)) report_fix = fix;
  else report_fix = ui_fix;
}

if (!isnull(report_fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + report_ver +
      '\n  Fixed version     : ' + report_fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Blue Coat ProxySG', version);
