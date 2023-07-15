#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134973);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id("CVE-2020-3951");
  script_xref(name:"VMSA", value:"2020-0005");
  script_xref(name:"IAVA", value:"2020-A-0119");

  script_name(english:"VMware Workstation 15.0.x < 15.5.2 Cortado Thinprint DoS (VMSA-2020-0005)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows host is 15.0.x prior to 15.5.2. It is, therefore,
affected by a flaw related to Cortado Thinprint and virtual printing that allows an attacker to overflow the heap
leading to denial of service conditions.  Note that Nessus has not tested for these issues but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0005.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 15.5.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3951");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Workstation");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

constraints = [
  { 'min_version' : '15.0', 'fixed_version' : '15.5.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
