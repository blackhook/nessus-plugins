#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154956);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/22");

  script_name(english:"Microsoft Windows Server Version 1809 Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows Server version 1809 is running on the remote host.
Microsoft ended support for Windows Server version 1809 on May 11, 2021.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2452f2e");
  # https://docs.microsoft.com/en-us/lifecycle/products/windows-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e760eea1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/08");

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

product_name  = "Windows Server version 1809";
tag           = "microsoft:windows_server_1809";
cpe_ver       = "-:*";

os = get_kb_item("SMB/WindowsVersion");
os_build = get_kb_item("SMB/WindowsVersionBuild");
os_name = get_kb_item("SMB/ProductName");

port	= get_kb_item("SMB/transport");

# No OS
if (!os) audit(AUDIT_HOST_NOT, "running an OS known to this plugin");

# Not Windows Server version 1809
if ("10" >!< os || "Windows 10" >< os_name) audit(AUDIT_OS_NOT, product_name);

# Not Windows Server running Long-Term Servicing Channel (LTSC)
if ("windows server 2019" >< tolower(os_name)) audit(AUDIT_OS_NOT, product_name);

# Not Windows Hyper-V server 2019
if ("hyper-v server 2019" >< tolower(os_name)) audit(AUDIT_OS_NOT, product_name);

# Not Build 17763 (version 1809)
if ("17763" != os_build) audit(AUDIT_OS_NOT, product_name);

# Both x86 and x64 exist in the CPE DB (xml file) from nvd.nist.gov.
arch = get_kb_item("SMB/ARCH");
if (!isnull(arch) && "x64" >< arch) edition = "x64";
else edition = "x86";

cpe_ver = ":" + edition;

register_unsupported_product(
  product_name  : product_name,
  is_custom_cpe : TRUE,
  cpe_class     : CPE_CLASS_OS,
  cpe_base      : tag,
  version       : cpe_ver
);

security_report_v4(port:port, severity:SECURITY_HOLE);
