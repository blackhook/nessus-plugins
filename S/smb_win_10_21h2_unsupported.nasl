#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(170963);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/02");

  script_name(english:"Microsoft Windows 10 Version 21H2 Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:"
The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows 10 version 21H2 is running on the remote host.
Microsoft ended support for Windows 10 version 21H2 on June 13, 2023.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # https://docs.microsoft.com/en-us/windows/release-health/status-windows-10-21H2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cc4f8d0");
  # https://docs.microsoft.com/en-US/lifecycle/announcements/windows-10-21H2-end-of-servicing
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa29d6e3");

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

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_reg_service_pack.nasl");
  script_exclude_keys("SMB/not_windows");
  script_require_ports("SMB/WindowsVersion", "SMB/WindowsVersionBuild");

  exit(0);
}

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

var now = get_kb_item("Flatline/nowtime");
if (empty_or_null(now))
  now = gettimeofday();

var product_name  = "Windows 10 version 21H2";
var tag           = "microsoft:windows_10";
var cpe_ver       = "-:*";

var os = get_kb_item("SMB/WindowsVersion");
var os_build = get_kb_item("SMB/WindowsVersionBuild");
var os_name = get_kb_item("SMB/ProductName");

var port	= get_kb_item("SMB/transport");

# No OS
if (!os) audit(AUDIT_HOST_NOT, "running an OS known to this plugin");

# Not Windows 10
if ("10" >!< os || "Windows Server" >< os_name) audit(AUDIT_OS_NOT, "Windows 10 version 21H2");

# future proof ourselves, plugin only kicks off if we've reached the first
# end of life date: 2023-06-13
if ((now < 1686614400))  
  audit(AUDIT_SUPPORTED, os_name);

# As per https://docs.microsoft.com/en-us/windows/release-health/release-information
#  we must treat version 21H2 different than 21H2 Enterprise/Education/IoT Enterprise
# EOS Date: Jun 11, 2024 12:00 EST
if ( now < 1718064000)
{
    if(
      "enterprise" >< tolower(os_name) ||
      "education" >< tolower(os_name)
  )
  {  
    audit(AUDIT_SUPPORTED, os_name);
  }
}

# Not Build 19044 (version 21H2)
# "19044" from https://microsoft.fandom.com/wiki/Windows_10_version_history#Version_21H2_(November_2021_Update)
if ("19044" != os_build) audit(AUDIT_OS_NOT, "Windows 10 version 21H2");

var edition = NULL;
# Both x86 and x64 exist in the CPE DB (xml file) from nvd.nist.gov.
var arch = get_kb_item("SMB/ARCH");
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