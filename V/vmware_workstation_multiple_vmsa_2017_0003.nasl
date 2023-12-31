#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97834);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2017-4898", "CVE-2017-4899", "CVE-2017-4900");
  script_bugtraq_id(96770, 96771, 96772);
  script_xref(name:"VMSA", value:"2017-0003");

  script_name(english:"VMware Workstation 12.x < 12.5.3 Multiple Vulnerabilities (VMSA-2017-0003)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is
12.x prior to 12.5.3. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in the vmware-vmx process when loading
    dynamic link library (DLL) files due to searching an
    insecure path, which was defined in a local environment
    variable. A local attacker can exploit this, via a
    specially crafted file injected into the path, to
    execute arbitrary code with SYSTEM privileges on the
    host. (CVE-2017-4898)

  - An out-of-bounds read error exists in the SVGA driver
    due to improper validation of certain input. A local
    attacker can exploit this within a VM to crash it or
    to disclose sensitive memory contents. (CVE-2017-4899)

  - A NULL pointer dereference flaw exists in the SVGA
    driver due to improper validation of certain input. A
    local attacker can exploit this within a VM to crash it.
    (CVE-2017-4900)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0003.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 12.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4898");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Workstation");

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
