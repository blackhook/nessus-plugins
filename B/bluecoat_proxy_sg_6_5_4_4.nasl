#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76165);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2010-5298", "CVE-2014-0198", "CVE-2014-0224");
  script_bugtraq_id(66801, 67193, 67899);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Blue Coat ProxySG 6.5.x Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Blue Coat ProxySG device's SGOS self-reported version is
6.5 prior to 6.5.4.4 and, therefore, contains a bundled version of
OpenSSL that contains multiple flaws. It is, therefore, potentially
affected by the following vulnerabilities :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - An error exists in the function 'do_ssl3_write' that
    could allow a NULL pointer to be dereferenced leading
    to denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material,
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)");
  script_set_attribute(attribute:"see_also", value:"https://bto.bluecoat.com/security-advisory/sa80");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.5.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/06");
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

if (version !~ "^6\.5\.") audit(AUDIT_HOST_NOT, "Blue Coat ProxySG 6.5.x");

report_fix = NULL;

# Select version for report
if (isnull(ui_version)) report_ver = version;
else report_ver = ui_version;

if (version =~ "^6\.5\." && ver_compare(ver:version, fix:"6.5.4.4", strict:FALSE) == -1)
{
  fix    = '6.5.4.4';
  ui_fix = '6.5.4.4 Build 0';

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
