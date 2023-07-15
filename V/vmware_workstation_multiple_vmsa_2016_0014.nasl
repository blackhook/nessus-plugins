#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93521);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id(
    "CVE-2016-7081",
    "CVE-2016-7082",
    "CVE-2016-7083",
    "CVE-2016-7084",
    "CVE-2016-7085",
    "CVE-2016-7086"
  );
  script_bugtraq_id(
    92934,
    92935,
    92940,
    92941
  );
  script_xref(name:"VMSA", value:"2016-0014");

  script_name(english:"VMware Workstation 12.x < 12.5.0 Multiple Vulnerabilities (VMSA-2016-0014)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is
12.x prior to 12.5.0. It is, therefore, affected by multiple
vulnerabilities :

  - A heap buffer overflow condition exists in Cortado
    ThinPrint due to improper validation of user-supplied
    input. An attacker on the guest can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code on the host system. (CVE-2016-7081)

  - A memory corruption issue exists in Cortado Thinprint
    due to improper handling of specially crafted EMF files.
    An attacker on the guest can exploit this to cause a
    denial of service condition or the execution of
    arbitrary code on the host system. (CVE-2016-7082)

  - A memory corruption issue exists in Cortado Thinprint
    due to improper handling of TrueType fonts embedded in
    EMFSPOOL. An attacker on the guest can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code on the host system. (CVE-2016-7083)

  - A memory corruption issue exists in Cortado Thinprint
    due to improper handling of specially crafted JPEG2000
    images. An attacker on the guest can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code on the host system. (CVE-2016-7084)

  - A flaw exits due to improper loading of some dynamic
    link library (DLL) files that allows an attacker to load
    a DLL file and thereby execute arbitrary code.
    (CVE-2016-7085)

  - A flaw exists in the Workstation installer due to
    insecure loading of executables. An attacker can exploit
    this, via a crafted application named 'setup64.exe'
    inserted into the same directory as the installer, to
    execute arbitrary code. (CVE-2016-7086)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0014.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 12.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7086");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Workstation");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '12.0', 'fixed_version' : '12.5.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
