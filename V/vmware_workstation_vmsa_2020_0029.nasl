##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144852);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/12");

  script_cve_id("CVE-2020-3999");
  script_xref(name:"VMSA", value:"2020-0029");
  script_xref(name:"IAVA", value:"2021-A-0007");

  script_name(english:"VMware Workstation 15.x < 15.5.7 DoS (VMSA-2020-0029)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected by a DoS vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is 15.x prior to 15.5.7. It is, therefore,
affected by a DoS vulnerability due to improper input validation in GuestInfo. A malicious actor with normal user
privilege access to a virtual machine can crash the virtual machine's vmx process leading to a denial of service
condition.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0029.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 15.5.7, 16, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3999");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_workstation_linux_installed.nbin");
  script_require_keys("installed_sw/VMware Workstation");

  exit(0);
}

include('vcf.inc');

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

app_info = vcf::get_app_info(app:'VMware Workstation', win_local:win_local);

constraints = [
  { 'min_version' : '15.0', 'fixed_version' : '15.5.7', 'fixed_display' : '15.5.7 / 16' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
