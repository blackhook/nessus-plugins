#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73834);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"MCAFEE-SB", value:"SB10071");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"McAfee Firewall Enterprise OpenSSL Information Disclosure (SB10071) (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee Firewall Enterprise installed
that is affected by an out-of-bounds read error, known as Heartbleed,
in the TLS/DTLS implementation due to improper handling of TLS
heartbeat extension packets. A remote attacker, using crafted packets,
can trigger a buffer over-read, resulting in the disclosure of up to
64KB of process memory, which contains sensitive information such as
primary key material, secondary key material, and other protected
content.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10071");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Apply 8.3.2 ePatch 14 per the vendor advisory.");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mcafee:firewall_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_firewall_enterprise_version.nbin");
  script_require_keys("Host/McAfeeFE/version", "Host/McAfeeFE/version_display", "Host/McAfeeFE/installed_patches");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "McAfee Firewall Enterprise";
version = get_kb_item_or_exit("Host/McAfeeFE/version");
version_display = get_kb_item_or_exit("Host/McAfeeFE/version_display");
installed_patches = get_kb_item_or_exit("Host/McAfeeFE/installed_patches");
hotfix = "8.3.2E14";
hotfix_display = "8.3.2 ePatch 14";

# Only 8.3.2 is affected. Furthermore, only Patch level 2 and below are affected.
if (version !~ "^8\.3\.2\." || ver_compare(ver:version, fix:"8.3.2.2", strict:FALSE) == 1) audit(AUDIT_INST_VER_NOT_VULN, version_display);

if (hotfix >!< installed_patches)
{
  port = 0;

  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed Version : ' + version_display +
      '\n  Patched Version   : ' + hotfix_display +
      '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix_display,app_name);
