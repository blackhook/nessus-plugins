#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59092);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id(
    "CVE-2012-1516",
    "CVE-2012-1517",
    "CVE-2012-2449",
    "CVE-2012-2450"
  );
  script_bugtraq_id(53369);
  script_xref(name:"VMSA", value:"2012-0009");

  script_name(english:"VMware Workstation Multiple Vulnerabilities (VMSA-2012-0009)");
  script_summary(english:"Checks VMware Workstation version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Workstation install detected on the remote host is 7.x
earlier than 7.1.6 or 8.0.x earlier than 8.0.3 and is, therefore,
potentially affected by the following vulnerabilities :

  - Memory corruption errors exist related to the
    RPC commands handler function which could cause the
    application to crash or possibly allow an attacker to
    execute arbitrary code. Note that these errors only
    affect the 3.x branch. (CVE-2012-1516, CVE-2012-1517)

  - An error in the virtual floppy device configuration
    can allow out-of-bounds memory writes and can allow
    a guest user to crash the VMX process or potentially
    execute arbitrary code on the host. Note that root or
    administrator level privileges in the guest are required
    for successful exploitation along with the existence of
    a virtual floppy device in the guest. (CVE-2012-2449)

  - An error in the virtual SCSI device registration
    process can allow improper memory writes and can allow
    a guest user to crash the VMX process or potentially
    execute arbitrary code on the host. Note that root or
    administrator level privileges are required in the
    guest for successful exploitation along with the
    existence of a virtual SCSI device in the guest.
    (CVE-2012-2450)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0009.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000176.html");
  # https://www.vmware.com/support/ws71/doc/releasenotes_ws716.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd5ac32f");
  # https://www.vmware.com/support/ws80/doc/releasenotes_workstation_803.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a550479");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 7.1.6 / 8.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1516");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Workstation/Version");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.1.6'},
  { 'min_version' : '8.0', 'fixed_version' : '8.0.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
