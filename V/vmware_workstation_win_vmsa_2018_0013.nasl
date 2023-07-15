#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110099);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2018-6963");
  script_bugtraq_id(104237);
  script_xref(name:"VMSA", value:"2018-0013");

  script_name(english:"VMware Workstation 14.x < 14.1.2 Multiple DoS (VMSA-2018-0013)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by multiple denial of service vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows
host is 14.x prior to 14.1.2. It is, therefore, missing a security
update that fixes multiple RPC related flaws that allow denial of
service attacks.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/us/security/advisories/VMSA-2018-0013.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 14.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6963");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Workstation");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '14.0', 'fixed_version' : '14.1.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
