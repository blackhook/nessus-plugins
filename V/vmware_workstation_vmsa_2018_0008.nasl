#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118980);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/21");

  script_cve_id("CVE-2018-6957");
  script_bugtraq_id(103431);
  script_xref(name:"VMSA", value:"2018-0008");

  script_name(english:"VMware Workstation 14.x < 14.1.1 Denial of Service Vulnerability (VMSA-2018-0008)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote
host is 14.x prior to 14.1.1. It is, therefore, affected by 
denial of service vulnerability which can be triggered by opening 
a large number of VNC sessions. In order for exploitation to be 
possible, VNC feature must be manually enabled.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0008.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 14.1.1, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6957");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_workstation_linux_installed.nbin");
  script_require_keys("installed_sw/VMware Workstation");

  exit(0);
}

include("vcf.inc");

if (get_kb_item("SMB/Registry/Enumerated")) win_local = TRUE;

app_info = vcf::get_app_info(app:"VMware Workstation", win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:2);

# VMWare Workstation 12.X is no longer supported
constraints = [
  { "min_version" : "14", "fixed_version" : "14.1.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

