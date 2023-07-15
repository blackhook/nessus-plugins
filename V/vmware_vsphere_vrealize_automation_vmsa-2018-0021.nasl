#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112209);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-3620");
  script_bugtraq_id(105080);
  script_xref(name:"VMSA", value:"2018-0021");

  script_name(english:"VMware vRealize Automation 6.x / 7.x Information Disclosure Vulnerability (VMSA-2018-0021");
  script_summary(english:"Checks the version of VMware vRealize Automation.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected
by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vRealize Automation installed on the remote
host is 6.x or 7.x. It is, therefore, affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0021.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/52497");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/52377");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Automation version 7.5.0 or later,
or implement operating system mitigations described in VMware kb article.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3620");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_automation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vRealize Automation/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");

app_name = "VMware vRealize Automation";

version = get_kb_item_or_exit("Host/VMware vRealize Automation/Version");

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/VMware vRealize Automation/Version");

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
    { "min_version" : "6.0.0", "fixed_version" : "7.5.0"  }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
