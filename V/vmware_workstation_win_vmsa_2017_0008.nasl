#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99590);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id(
    "CVE-2017-4908",
    "CVE-2017-4909",
    "CVE-2017-4910",
    "CVE-2017-4911",
    "CVE-2017-4912",
    "CVE-2017-4913"
  );
  script_bugtraq_id(
    97911,
    97912,
    97913,
    97916,
    97920,
    97921
  );
  script_xref(name:"VMSA", value:"2017-0008");

  script_name(english:"VMware Workstation 12.x < 12.5.3 Multiple Vulnerabilities (VMSA-2017-0008)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows host
is 12.x prior to 12.5.3. It is, therefore, affected by multiple
vulnerabilities :

  - A heap buffer overflow condition exists in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    JPEG2000 files. An attacker on the guest can exploit
    this to cause a denial of service condition or the
    execution or arbitrary code on the host system.
    (CVE-2017-4908)

  - A heap buffer overflow condition exists in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    TrueType Fonts. An attacker on the guest can exploit
    this to cause a denial of service condition or the
    execution or arbitrary code on the host system.
    (CVE-2017-4909)

  - Out-of-bounds read and write errors exist in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    JPEG2000 files. An attacker on the guest can exploit
    these to corrupt memory, resulting in a denial of
    service condition or the execution of arbitrary code on
    the host system. (CVE-2017-4910, CVE-2017-4911)

  - Out-of-bounds read and write errors exist in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    TrueType Fonts. An attacker on the guest can exploit
    these to corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code on the host
    system. (CVE-2017-4912)

  - An integer overflow condition exists in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    TrueType Fonts. An attacker on the guest can exploit
    this to corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code on the host
    system. (CVE-2017-4913)

The above vulnerabilities can be exploited only if virtual printing
has been enabled. This feature is not enabled by default on VMware
Workstation.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0008.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 12.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4908");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Workstation", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '12.0', 'fixed_version' : '12.5.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
