#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129498);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2019-5527");
  script_xref(name:"VMSA", value:"2019-0014");
  script_xref(name:"IAVA", value:"2019-A-0344");

  script_name(english:"VMware Horizon View Client 5.x < 5.2.0 Use-After-Free (VMSA-2019-0014)");
  script_summary(english:"Checks the VMware Horizon View Client version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected by a use-after-free error.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View Client installed on the remote host is 5.x prior to 5.2.0. It is, therefore,
affected by a use-after-free error in the virtual sound device that allows a local attacker on the guest machine with
low privileges to execute code on the host.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0014.html");
  script_set_attribute(attribute:"solution", value:
"Update to Horizon View Client version 5.2.0, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_horizon_view_client_installed_nix.nbin", "vmware_horizon_view_client_installed.nbin", "macosx_vmware_horizon_view_client_installed.nbin");
  script_require_keys("installed_sw/VMware Horizon View Client");

  exit(0);
}

include('vcf.inc');

if (get_kb_item("SMB/Registry/Enumerated")) win_local = TRUE;

app_info = vcf::get_app_info(app:'VMware Horizon View Client', win_local:win_local);

constraints = [{ 'min_version' : '5', 'fixed_version' : '5.2.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
