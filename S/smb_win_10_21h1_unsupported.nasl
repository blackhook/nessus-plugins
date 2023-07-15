##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(170962);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/02");

  script_name(english:"Microsoft Windows 10 Version 21H1 Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:"
The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows 10 version 21H1 is running on the remote host.
Microsoft ended support for Windows 10 version 21H1 on Dec 13, 2022.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-21h1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8512a577");
  # https://docs.microsoft.com/en-US/lifecycle/announcements/windows-10-21H1-end-of-servicing
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/ub2c509f6?");

  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_reg_service_pack.nasl");
  script_exclude_keys("SMB/not_windows");
  script_require_ports("SMB/WindowsVersion", "SMB/WindowsVersionBuild");

  exit(0);
}

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

var product_name  = "Windows 10 version 21H1";
var tag           = "microsoft:windows_10";
var cpe_ver       = "-:*";

var os = get_kb_item("SMB/WindowsVersion");
var os_build = get_kb_item("SMB/WindowsVersionBuild");
var os_name = get_kb_item("SMB/ProductName");

var port	= get_kb_item("SMB/transport");

# No OS
if (!os) audit(AUDIT_HOST_NOT, "running an OS known to this plugin");

# Not Windows 10
if ("10" >!< os) audit(AUDIT_OS_NOT, "Windows 10");

# Not Build 19043 (version 21H1)
# "19043" from https://microsoft.fandom.com/wiki/Windows_10_version_history#:~:text=Accessibility%20improvements-,Version%2021H1%20(October%202020%20Update),the%20May%202020%20Update%2C%20and%20carries%20the%20build%20number%2010.0.19042.,-The%20first%20preview
if ("19043" != os_build) audit(AUDIT_OS_NOT, product_name);

# Both x86 and x64 exist in the CPE DB (xml file) from nvd.nist.gov.
var arch = get_kb_item("SMB/ARCH");
var edition = NULL;
if (!isnull(arch) && "x64" >< arch) edition = "x64";
else edition = "x86";

cpe_ver = ":" + edition;

register_unsupported_product(
  product_name : product_name,
  cpe_class    : CPE_CLASS_OS,
  cpe_base     : tag,
  version      : cpe_ver
);

security_report_v4(port:port, severity:SECURITY_HOLE);