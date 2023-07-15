##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143223);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/04");

  script_cve_id("CVE-2020-4004");
  script_xref(name:"VMSA", value:"2020-0026");
  script_xref(name:"IAVA", value:"2020-A-0544");

  script_name(english:"VMware Workstation 15.x < 15.5.7 Use-after-free (VMSA-2020-0026)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by a use-after-free error.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows host is 15.x prior to 15.5.7. It is, therefore,
affected by a use-after-free error in the XHCI USB Controller. An unauthenticated, local attacker with administrative
privileges on a virtual machine may exploit this issue to execute code as the virtual machine's VMX process running on
the host.

Note that Nessus has not tested for this issue, but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0026.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 15.5.7, 16, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4004");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_workstation_linux_installed.nbin");
  script_require_keys("installed_sw/VMware Workstation", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Cannot check if XHCI USB Controller is used
if (report_paranoia < 2) audit(AUDIT_PARANOID);

windows = get_kb_item('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'VMware Workstation', win_local:windows);

constraints = [
  { 'min_version' : '15.0', 'fixed_version' : '15.5.7', 'fixed_display' : '15.5.7 / 16' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
