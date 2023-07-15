#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105787);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-4948");
  script_bugtraq_id(102441);
  script_xref(name:"VMSA", value:"2018-0003");

  script_name(english:"VMware Horizon View Client 4.x < 4.7.0 Multiple Vulnerabilities (VMSA-2018-0003)");
  script_summary(english:"Checks the VMware Horizon View Client version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View Client installed on the remote host
is 4.x prior to 4.7.0. It is, therefore, affected by multiple
vulnerabilities including disclosure of memory contents and a DoS.

Note that exploitation requires that virtual printing is enabled
(disabled by default on Workstation, but enabled by default on Horizon
View). Furthermore, the vendor states that the vulnerability needs to
be used in conjunction with other bugs without further clarification.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0003.html");
  script_set_attribute(attribute:"see_also", value:"https://securitytracker.com/id/1040108");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View Client 4.7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4948");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_horizon_view_client_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Horizon View Client");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"VMware Horizon View Client", win_local:TRUE);

constraints = [{ "min_version" : "4", "fixed_version" : "4.7.0" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
