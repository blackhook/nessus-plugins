#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104853);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id(
    "CVE-2017-4934",
    "CVE-2017-4935",
    "CVE-2017-4936",
    "CVE-2017-4937",
    "CVE-2017-4938",
    "CVE-2017-4939"
  );
  script_bugtraq_id(
    101887,
    101890,
    101892,
    101903
  );
  script_xref(name:"VMSA", value:"2017-0018");
  script_xref(name:"ZDI", value:"ZDI-17-921");
  script_xref(name:"ZDI", value:"ZDI-17-922");

  script_name(english:"VMware Workstation 12.x < 12.5.8 Multiple Vulnerabilities (VMSA-2017-0018)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by a guest-to-host arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Windows host
is 12.x prior to 12.5.8. It is, therefore, affected by multiple
vulnerabilities including arbitrary code execution and a local DoS.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0018.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-921/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-922/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 12.5.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/29");

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
  { 'min_version' : '12.0', 'fixed_version' : '12.5.8'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
