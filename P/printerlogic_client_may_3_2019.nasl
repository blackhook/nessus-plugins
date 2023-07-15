#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152101);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/28");

  script_cve_id("CVE-2018-5408", "CVE-2018-5409", "CVE-2019-9505");

  script_name(english:"PrinterLogic Client Multiple Vulnerabilities (May 3, 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PrinterLogic Client installed on the remote host is affected by the following vulnerabilities:

  - The PrinterLogic Print Management software does not validate, or incorrectly validates, the PrinterLogic
    management portal's SSL certificate. When a certificate is invalid or malicious, it might allow an
    attacker to spoof a trusted entity by using a man-in-the-middle (MITM) attack. The software might connect
    to a malicious host while believing it is a trusted host, or the software might be deceived into accepting
    spoofed data that appears to originate from a trusted host. (CVE-2018-5408)

  - The PrinterLogic Print Management software updates and executes the code without sufficiently verifying
    the origin and integrity of the code. An attacker can execute malicious code by compromising the host
    server, performing DNS spoofing, or modifying the code in transit. (CVE-2018-5409)

  - The PrinterLogic Print Management software does not sanitize special characters allowing for remote
    unauthorized changes to configuration files. An unauthenticated attacker may be able to remotely execute
    arbitrary code with SYSTEM privileges. (CVE-2019-9505)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.printerlogic.com/security-bulletin/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PrinterLogic software for Windows version 25.0.0.49 or later, or PrinterLogic software for Mac and
Linux version 25.1.0.274 or later, and apply the configuration mentioned in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9505");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:printerlogic:print_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("printerlogic_printer_installer_client_mac_installed.nbin", "printerlogic_printer_installer_client_nix_installed.nbin", "printerlogic_printer_installer_client_win_installed.nbin", "os_fingerprint.nasl");
  script_require_ports("installed_sw/PrinterLogic Printer Installer Client");

  exit(0);
}

include('vcf.inc');

var os = get_kb_item_or_exit('Host/OS');
var app_info;
var win_local = FALSE;
var constraints;
var app_name = 'PrinterLogic Printer Installer Client';

if (tolower(os) =~ 'windows')
{
  get_kb_item_or_exit('SMB/Registry/Enumerated');
  win_local = TRUE;
  app_info = vcf::get_app_info(app:app_name, win_local:TRUE);
  constraints = [
    { 'fixed_version' : '25.0.0.49' }
  ];

}
else if (tolower(os) =~ 'linux|mac os')
{
  get_kb_item_or_exit('Host/local_checks_enabled');
  app_info = vcf::get_app_info(app:app_name);
  constraints = [
    { 'fixed_version' : '25.1.0.274' }
  ];
}
else
{
  audit(AUDIT_OS_NOT,'affected');
}

# Require paranoia to flag on package manager install
if ('via package manager' >< app_info.path && report_paranoia < 2)
  audit(AUDIT_MANAGED_INSTALL, app_name);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
