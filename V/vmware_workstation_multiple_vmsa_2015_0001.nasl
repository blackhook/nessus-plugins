#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81187);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id(
    "CVE-2014-8370",
    "CVE-2015-1043",
    "CVE-2015-1044",
    "CVE-2015-2341"
  );
  script_bugtraq_id(
    72336,
    72337,
    72338,
    75094
  );
  script_xref(name:"VMSA", value:"2015-0001");
  script_xref(name:"VMSA", value:"2015-0004");

  script_name(english:"VMware Workstation 10.x < 10.0.5 Multiple Vulnerabilities (VMSA-2015-0001 / VMSA-2015-0004) (Windows)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows host
is 10.x prior to 10.0.5. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists that allows a local attacker
    to escalate privileges or cause a denial of service
    via an arbitrary write to a file. (CVE-2014-8370)

  - An input validation error exists in the Host Guest File
    System (HGFS) that allows a local attacker to cause a
    denial of service of the guest operating system.
    (CVE-2015-1043)

  - An input validation error exists in the VMware
    Authorization process (vmware-authd) that allows a
    remote attacker to cause a denial of service of the host
    operating system. (CVE-2015-1044)

  - A denial of service vulnerability exists due to improper
    validation of user-supplied input to a remote procedure
    call (RPC) command. An unauthenticated, remote attacker
    can exploit this, via a crafted command, to crash the
    host or guest operating systems. (CVE-2015-2341)");
  # http://lists.vmware.com/pipermail/security-announce/2015/000286.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bded33c");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0004.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 10.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8370");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Workstation/Version", "VMware/Workstation/Path");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '10.0', 'fixed_version' : '10.0.5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
