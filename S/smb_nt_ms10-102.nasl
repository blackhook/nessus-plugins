#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51174);
  script_version("1.20");
  script_cvs_date("Date: 2018/11/15 20:50:30");

  script_cve_id("CVE-2010-3960");
  script_bugtraq_id(45293);
  script_xref(name:"MSFT", value:"MS10-102");
  script_xref(name:"MSKB", value:"2345316");

  script_name(english:"MS10-102: Vulnerability in Hyper-V Could Allow Denial of Service (2345316)");
  script_summary(english:"Checks version of Vmbus.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is affected by a denial of service flaw that exists
in Hyper-V.  Sending a specially crafted packet to the VMBus can cause
the service to become non-responsive.

This can reportedly only be exploited by authenticated users from one
of the guest virtual machines hosted by the Hyper-V server."
  );
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2010/ms10-102");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2008 and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_server_features.nbin", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-102';
kbs = make_list("2345316");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# V1.1 of MS10-102 says the update can only be installed on affected
# systems with the Hyper-V role enabled. [V1.0 says it could be
# installed manually on such systems.]
#
# (Hyper-V ID = 20)
#
if (!get_kb_item('WMI/server_feature/20')) exit(0, 'Hyper-V is not enabled, therefore the host is not affected.');


kb = "2345316";
if (
  # Win2008 R2
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Vmbus.sys", version:"6.1.7600.16701", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Vmbus.sys", version:"6.1.7600.20834", min_version:"6.1.7600.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)  ||

  # Win2008
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:1, file:"Vmbus.sys", version:"6.0.6001.18538", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:1, file:"Vmbus.sys", version:"6.0.6001.22777", min_version:"6.0.6001.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)  ||
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:2, file:"Vmbus.sys", version:"6.0.6002.18327", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:2, file:"Vmbus.sys", version:"6.0.6002.22505", min_version:"6.0.6002.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-102", value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
