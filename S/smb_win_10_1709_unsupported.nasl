#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124117);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/25");

  script_xref(name:"IAVA", value:"0001-A-0020");

  script_name(english:"Microsoft Windows Version 1709 Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:"
The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows version 1709 is running on the remote host.
End of Support dates for all affected Operating Systems are listed below;
- Windows 10 version 1709 Home/Pro on April 9, 2019.
- Windows 10 version 1709 Enterprise/Educational on October 13, 2020.
- Windows Server 2016 version 1709 on April 9, 2019.

Note: Microsoft extended support for Windows 10 Enterprise/Education on March 19, 2020. The
previous end date was April 14, 2020.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2452f2e");
  # https://techcommunity.microsoft.com/t5/windows-it-pro-blog/revised-end-of-service-date-for-windows-10-version-1709-october/ba-p/1239043
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19b786f0");
  # https://docs.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa29d6e3");
  # https://docs.microsoft.com/en-us/lifecycle/products/windows-10-enterprise-and-education
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?807cb358");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/lifecycle/products/windows-server");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_reg_service_pack.nasl");
  script_exclude_keys("SMB/not_windows");
  script_require_ports("SMB/WindowsVersion", "SMB/WindowsVersionBuild");

  exit(0);
}

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

cpe_ver   = "-:*";

os = get_kb_item("SMB/WindowsVersion");
os_build = get_kb_item("SMB/WindowsVersionBuild");
os_name = get_kb_item("SMB/ProductName");

port	= get_kb_item("SMB/transport");

# No OS
if (!os) audit(AUDIT_HOST_NOT, "running an OS known to this plugin");

# Not Windows 10
if ("10" >!< os) audit(AUDIT_OS_NOT, "Windows 10 / Windows Server 2016");

# Windows 10 or Windows Sever
if ('10' >< os_name)
{
  os_name_new = 'Windows 10 version 1709';
  tag       = "microsoft:windows_10";
}

if ('Server' >< os_name)
{
  os_name_new = 'Windows Server 2016 version 1709';
  tag       = "microsoft:windows_server_2016";
}


# Not Build 16299 (version 1709)
if ("16299" != os_build) audit(AUDIT_OS_NOT, os_name_new);

if (
  (unixtime() < 1602648000) &&
  ("enterprise" >< tolower(os_name) ||
   "education" >< tolower(os_name))
  ) audit(AUDIT_OS_NOT, "affected");


# Both x86 and x64 exist in the CPE DB (xml file) from nvd.nist.gov.
arch = get_kb_item("SMB/ARCH");
if (!isnull(arch) && "x64" >< arch) edition = "x64";
else edition = "x86";

cpe_ver = ":" + edition;

register_unsupported_product(
  product_name : os_name_new,
  cpe_class    : CPE_CLASS_OS,
  cpe_base     : tag,
  version      : cpe_ver
);

security_report_v4(port:port, severity:SECURITY_HOLE);
