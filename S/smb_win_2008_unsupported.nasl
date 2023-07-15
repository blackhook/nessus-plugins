#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122614);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/28");

  script_xref(name:"IAVA", value:"0001-A-0021");

  script_name(english:"Microsoft Windows Server 2008 Unsupported Version Detection");
  script_summary(english:"Checks the OS / SMB fingerprint.");

  script_set_attribute(attribute:"synopsis", value:"
The remote operating system is no longer supported.");
  script_set_attribute(attribute:"description", value:
"Microsoft Windows Server 2008 is running on the remote host.
Microsoft ended support for Windows Server 2008 versions lower than
Service Pack 2 on 4/9/2011 and all other versions on 1/14/2020.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities. Furthermore, Microsoft is unlikely to
investigate or acknowledge reports of vulnerabilities.");
  # https://support.microsoft.com/en-us/help/4456235/end-of-support-for-windows-server-2008-and-windows-server-2008-r2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?883c9d9f");
  # https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2452f2e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft Windows that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported OS.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_reg_service_pack.nasl", "wmi_win_7_2008r2_esu_status.nbin");
  script_exclude_keys("SMB/not_windows");
  script_require_ports("SMB/WindowsVersion", "SMB/ProductName", "SMB/CSDVersion");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

tag = "microsoft:windows_server_2008";
cpe_ver = "";
os = get_kb_item_or_exit("SMB/WindowsVersion");
os_name = get_kb_item_or_exit("SMB/ProductName");
sp = get_kb_item("SMB/CSDVersion");
if ( sp )
{
  sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:sp, replace:"\1");
  sp = int(sp);
}
else sp = 0;

# Not Windows Server 2008
if ("6.0" >!< os || "Vista" >< os_name) audit(AUDIT_OS_NOT, "Windows Server 2008");

if(get_kb_item("WMI/W7_2008R2_ESU")) audit(AUDIT_SUPPORTED, os_name);

if(sp == 1)
  cpe_ver = ":sp1";
else if(sp == 2)
  cpe_ver = ':sp2';

# Both x86 and x64 exist in the CPE DB (xml file) from nvd.nist.gov.
arch = get_kb_item("SMB/ARCH");
if (!isnull(arch) && "x64" >< arch) edition = "x64";
else edition = "x86";

cpe_ver = cpe_ver + ":" + edition;

register_unsupported_product(
  product_name : os_name,
  cpe_class    : CPE_CLASS_OS,
  cpe_base     : tag,
  version      : cpe_ver
);

security_report_v4(severity:SECURITY_HOLE, port:0);
