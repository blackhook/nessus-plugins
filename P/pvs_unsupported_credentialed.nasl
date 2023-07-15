#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71460);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_xref(name:"IAVA", value:"0001-A-0603");

  script_name(english:"Tenable Passive Vulnerability Scanner Unsupported Version Detection (credentialed check)");
  script_summary(english:"Checks the PVS version.");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerability scanner application installed on the remote host is no
longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Tenable Passive Vulnerability Scanner (PVS) on the remote host is no
longer supported. The product name has subsequently been changed to Nessus Network Monitor (NNM).

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/products/passive-vulnerability-scanner/faq");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Tenable Nessus Network Monitor (NNM) that is currently supported.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:pvs");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 Tenable Network Security, Inc.");

  script_dependencies("pvs_installed_win.nbin", "pvs_installed_nix.nbin", "pvs_installed_macosx.nbin", "os_fingerprint.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item_or_exit("Host/OS");

if ('windows' >< tolower(os))
{
  version = get_kb_item_or_exit("SMB/PVS/Version");
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;
}
else
{
  version = get_kb_item("Host/PVS/Version");
  if (empty_or_null(version))
  {
    install = get_single_install(
      app_name:"Tenable Passive Vulnerability Scanner",
      exit_if_unknown_ver:TRUE
    );
    version = install['version'];
  }
  port = 0;
}

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 5 || (ver[0] == 5 && ver[1] < 4) )
{
  report =
    '\n  Installed version  : ' + version +
    '\n  Supported versions : Upgrade to Nessus Network Monitor (NNM)\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'PVS', version);
