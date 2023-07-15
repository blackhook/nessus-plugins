#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63077);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2012-5458", "CVE-2012-5459");
  script_bugtraq_id(56469, 56470);
  script_xref(name:"VMSA", value:"2012-0015");

  script_name(english:"VMware Workstation 8.x < 8.0.5 Multiple Vulnerabilities (VMSA-2012-0015)");
  script_summary(english:"Checks VMware Workstation version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a virtualization application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The VMware Workstation 8.x install detected on the remote host is
earlier than 8.0.5 and is, therefore, potentially affected by the
following vulnerabilities :

  - Certain processes, when created, have weak security
    permissions assigned.  It is possible to commandeer
    these process threads, which could result in elevation
    of privileges in the context of the host. (CVE-2012-5458)

  - A DLL binary planning vulnerability exists that could be
    exploited by an attacker to execute arbitrary code on
    the remote host. (CVE-2012-5459)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2012-0015.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000193.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Workstation 8.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5458");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "VMware/Workstation/Version");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
