#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72821);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/24 18:56:13");

  script_cve_id("CVE-2012-6595", "CVE-2012-6600");
  script_bugtraq_id(62120, 62131);

  script_name(english:"Palo Alto Networks PAN-OS < 4.0.9 / 4.1.x < 4.1.2 Multiple Command Injections");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by multiple command injection
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Palo Alto Networks PAN-OS
prior to 4.0.9 / 4.1.2.  It is, therefore, affected by multiple
command injection vulnerabilities :

  - A vulnerability exists that allows an authenticated user
    to inject arbitrary shell commands via the CLI.
    (CVE-2012-6595 / PAN-SA-2012-0006)

  - A vulnerability exists that allows an authenticated user
    to inject arbitrary shell commands via the CLI.
    (CVE-2012-6600 / PAN-SA-2012-0011)

Note that the 3.0 branch is not affected by these vulnerabilities."
  );
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/6");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS version 4.0.9 / 4.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = NULL;

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

# 3.0.x is not affected
if (version =~ "^3\.0($|[^0-9])") audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

if (version =~ "^4\.1($|[^0-9])")
  fix = "4.1.2";
else
  fix = "4.0.9";

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(extra:report, port:0);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
