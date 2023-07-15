#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149377);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/25");

  script_name(english:"Microsoft Windows 10 Version 1909 Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:"
The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows 10 version 1909 is running on the remote host.
Microsoft ended support for Windows 10 version 1909 on May 11, 2021.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # https://docs.microsoft.com/en-us/windows/release-health/status-windows-10-1909
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1031ea07");
  # https://docs.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa29d6e3");

  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_reg_service_pack.nasl");
  script_exclude_keys("SMB/not_windows");
  script_require_ports("SMB/WindowsVersion", "SMB/WindowsVersionBuild");

  exit(0);
}

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

product_name  = "Windows 10 version 1909";
tag           = "microsoft:windows_10";
cpe_ver       = "-:*";

os = get_kb_item("SMB/WindowsVersion");
os_build = get_kb_item("SMB/WindowsVersionBuild");
os_name = get_kb_item("SMB/ProductName");

port	= get_kb_item("SMB/transport");

# No OS
if (!os) audit(AUDIT_HOST_NOT, "running an OS known to this plugin");

# Not Windows 10
if ("10" >!< os || "Windows Server" >< os_name) audit(AUDIT_OS_NOT, "Windows 10");

# As per https://docs.microsoft.com/en-us/windows/release-health/release-information
#  we must treat version 1909 different than 1909 Enterprise/Education
# Note that this also differs from how version 1903 was handled.
# EOS Date: May 10, 2022 12:00 EST
if (
    (unixtime() < 1652198400) &&
    ("enterprise" >< tolower(os_name) ||
    "education" >< tolower(os_name))
  )  
  audit(AUDIT_SUPPORTED, os_name);

# Not Build 18363 (version 1909)
# "18363" from https://microsoft.fandom.com/wiki/Windows_10_version_history#:~:text=Windows%2010%20May%202019%20Update,%22%20or%20%22Threshold%22%20codename.
if ("18363" != os_build) audit(AUDIT_OS_NOT, product_name);

# Both x86 and x64 exist in the CPE DB (xml file) from nvd.nist.gov.
arch = get_kb_item("SMB/ARCH");
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
