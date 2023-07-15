#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73515);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"Blue Coat ProxySG Heartbeat Information Disclosure (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is potentially affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Blue Coat ProxySG device's SGOS self-reported version is
6.5.3.x prior to 6.5.3.6. It is, therefore, potentially affected by an
information disclosure vulnerability.

An out-of-bounds read error, known as the 'Heartbleed Bug', exists
related to handling TLS heartbeat extensions that could allow an
attacker to obtain sensitive information such as primary key material,
secondary key material, and other protected content.");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa79");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.5.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

if (version =~ "^6\.5\.3($|[^0-9])")
{
  fix    = '6.5.3.6';
  ui_fix = '6.5.3.6 Build 0';
}
else audit(AUDIT_INST_VER_NOT_VULN, "Blue Coat ProxySG", version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    # Select format for output
    if (isnull(ui_version))
    {
      report_ver = version;
      report_fix = fix;
    }
    else
    {
      report_ver = ui_version;
      report_fix = ui_fix;
    }

    report =
      '\n  Installed version : ' + report_ver +
      '\n  Fixed version     : ' + report_fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Blue Coat ProxySG", version);
