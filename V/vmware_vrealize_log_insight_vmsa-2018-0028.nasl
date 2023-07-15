#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119015);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2018-6980");
  script_bugtraq_id(105925);
  script_xref(name:"VMSA", value:"2018-0028");
  script_xref(name:"IAVB", value:"2018-B-0144-S");

  script_name(english:"VMware vRealize Log Insight 4.6.x < 4.6.2 / 4.7.x < 4.7.1 Authorization Bypass Vulnerability (VMSA-2018-0028)");
  script_summary(english:"Checks the version of VMware vRealize Log Insight.");

  script_set_attribute(attribute:"synopsis", value:
"A log management application running on the remote host is affected by
an authorization bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware vRealize Log Insight application running on the remote host
is 4.6.x < 4.6.2 or 4.7.x < 4.7.1. It is, therefore, affected by an
authorization bypass vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0028.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vRealize Log Insight version 4.6.2 or 4.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_log_insight");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_log_insight_webui_detect.nbin", "vmware_vrealize_log_insight_nix.nbin");
  script_require_keys("installed_sw/VMware vRealize Log Insight");

  exit(0);
}

include("audit.inc");
include("http.inc");
include("vcf.inc");

app = "VMware vRealize Log Insight";

get_install_count(app_name:app, exit_if_zero:TRUE);

local_installs = get_installs(app_name:app);
if (local_installs[0] == IF_OK)
{
  app_info = vcf::get_app_info(app:app);
}
else
{
  # only check remote if we have no local installs
  port = get_http_port(default:443);
  app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
}

constraints = [
  { "min_version" : "4.6.0", "fixed_version" : "4.6.2" },
  { "min_version" : "4.7.0", "fixed_version" : "4.7.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
