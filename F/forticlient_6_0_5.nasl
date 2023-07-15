#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123009);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/22 12:41:13");

  script_name(english:"Fortinet FortiClient Local Privilege Escalation");
  script_summary(english:"Checks the version of FortiClient.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities
that can lead to privilege escalation.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiClient running on the remote host is
prior to 6.0.5. It is, therefore, affected by a privilege escalation
vulnerability. An unauthenticated, remote attacker can exploit this
to gain privileged or administrator access to the system.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-108");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 6.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("installed_sw/FortiClient");
app_info = vcf::get_app_info(app:"FortiClient");

constraints = [
  {"fixed_version" : "6.0.5"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
