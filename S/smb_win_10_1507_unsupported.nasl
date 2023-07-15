#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100064);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/25");

  script_xref(name:"IAVA", value:"0001-A-0020");

  script_name(english:"Microsoft Windows 10 Version 1507 Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:"
The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows 10 version 1507 is running on the remote host.
Microsoft ended support for Windows 10 version 1507 on May 9, 2017.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # https://support.microsoft.com/en-us/help/4015562/windows-10-version-1507-will-no-longer-receive-security-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67b17ad4");
  # https://docs.microsoft.com/en-us/windows/release-health/release-information
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f33b3fd");
  # https://docs.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?807cb358");
  # https://docs.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa29d6e3");
  
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("smb_reg_service_pack.nasl");
  script_exclude_keys("SMB/not_windows");
  script_require_ports("SMB/WindowsVersion", "SMB/WindowsVersionBuild");

  exit(0);
}

if (get_kb_item('SMB/not_windows')) audit(AUDIT_OS_NOT, 'Windows');

product_name  = "Windows 10 version 1507";
tag           = "microsoft:windows_10";
cpe_ver       = "-:*";

os = get_kb_item('SMB/WindowsVersion');
os_build = get_kb_item('SMB/WindowsVersionBuild');
os_name = get_kb_item('SMB/ProductName');

port	= get_kb_item("SMB/transport");

# No OS
if (!os) audit(AUDIT_HOST_NOT, 'running an OS known to this plugin');

# Not Windows 10
if ('10' >!< os || "Windows Server" >< os_name) audit(AUDIT_OS_NOT, 'Windows 10');

# Not Build 10240 (version 1507)
if ('10240' != os_build) audit(AUDIT_OS_NOT, product_name);

# LTSB version - EOL on mainstream support ended on 5/11/21, per: 
# -  https://docs.microsoft.com/en-us/windows/release-health/release-information
# Extended support ends on 10/14/25, everyone receives free security updates, per: 
# -  https://docs.microsoft.com/en-us/lifecycle/end-of-support/end-of-support-2021#products-moving-to-extended-support
# if customer has an ESU subscription after extended support then we will need to analyze/update detection.
if (
  (unixtime() < 1760414400) &&
  ('enterprise' >< tolower(os_name) ||
  'ltsb' >< tolower(os_name))
)  
audit(AUDIT_SUPPORTED, os_name);

# Both x86 and x64 exist in the CPE DB (xml file) from nvd.nist.gov.
arch = get_kb_item('SMB/ARCH');
if (!isnull(arch) && 'x64' >< arch) edition = 'x64';
else edition = 'x86';

cpe_ver = ":" + edition;

register_unsupported_product(
  product_name : product_name,
  cpe_class    : CPE_CLASS_OS,
  cpe_base     : tag,
  version      : cpe_ver
);

security_report_v4(port:port, severity:SECURITY_HOLE);
