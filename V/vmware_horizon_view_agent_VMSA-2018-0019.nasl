#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111601);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/20");

  script_cve_id("CVE-2018-6970");
  script_bugtraq_id(105031);
  script_xref(name:"VMSA", value:"2018-0019");

  script_name(english:"VMware Horizon View Agent 6.x < 6.2.7 / 7.x < 7.5.1 Local Information Disclosure Vulnerability (VMSA-2018-0019)");
  script_summary(english:"Checks VMware View Agent version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtual desktop agent installed that is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware Horizon View Agent installed on the remote host is 6.x
prior to 6.2.7 or 7.x prior to 7.5.1. It is, therefore, affected by an
information disclosure vulnerability related to the Message Framework
library.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0019.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View Agent 6.2.7, 7.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6970");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_view_agent_detect.nasl");
  script_require_keys("installed_sw/VMware View Agent");

  exit(0);
}

include("vcf.inc");

app = "VMware View Agent";

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { "min_version": "6", "fixed_version" : "6.2.7" },
  { "min_version": "7", "fixed_version" : "7.5.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
