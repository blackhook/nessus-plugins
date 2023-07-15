#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131129);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/20");

  script_cve_id(
    "CVE-2019-5540",
    "CVE-2019-5541",
    "CVE-2019-5542",
    "CVE-2019-11135"
  );
  script_xref(name:"VMSA", value:"2019-0020");
  script_xref(name:"VMSA", value:"2019-0021");

  script_name(english:"VMware Workstation 15.0.x < 15.5.1 Multiple Vulnerabilities (VMSA-2019-0020, VMSA-2019-0021)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows host is 15.0.x prior to 15.5.1. It is, therefore,
affected by multiple vulnerabilities:

  - An unspecified information disclosure vulnerability in vmnetdhcp. (CVE-2019-5540)

  - An unspecified out-of-bounds write vulnerability in the e1000e virtual network adapter. (CVE-2019-5541)

  - An unspecified denial-of-service vulnerability in the RPC handler. (CVE-2019-5542)

  - Unspecified vulnerabilities related to hypervisor-specific mitigations for TSX Asynchronous Abort (TAA).
    (CVE-2019-11135)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0020.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2019-0021.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 15.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5541");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Workstation");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

constraints = [
  { 'min_version' : '15.0', 'fixed_version' : '15.5.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
