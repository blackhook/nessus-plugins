#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59730);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2012-3288", "CVE-2012-3289");
  script_bugtraq_id(53996);
  script_xref(name:"VMSA", value:"2012-0011");

  script_name(english:"VMware Workstation Multiple Vulnerabilities (VMSA-2012-0011)");
  script_summary(english:"Checks VMware Workstation version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware Workstation install detected on the remote host is 7.x
earlier than 7.1.6, or 8.0.x earlier than 8.0.4 and is, therefore,
potentially affected by the following vulnerabilities :

  - A memory corruption error exists related to the
    handling of 'Checkpoint' files that can allow arbitrary
    code execution. (CVE-2012-3288)

  - An error exists related to handling traffic from
    remote physical devices, e.g. CD-ROM or mouse that
    can cause the virtual machine to cash. Note that this
    issue only affects the 8.x branch. (CVE-2012-3289)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0011.html");
  # https://www.vmware.com/support/ws71/doc/releasenotes_ws716.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd5ac32f");
  # https://www.vmware.com/support/ws80/doc/releasenotes_workstation_804.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb58e81d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 7.1.6 / 8.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3288");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

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
  { 'min_version' : '8.0', 'fixed_version' : '8.0.4'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
