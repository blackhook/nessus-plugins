#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119779);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2018-1002105");
  script_bugtraq_id(106068);

  script_name(english:"Rancher < 1.6.25 / 2.0.9 / 2.1.3 Kubernetes Proxy Request Handling");

  script_set_attribute(attribute:"synopsis", value:
"A Docker container of Rancher installed on the remote host is
missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of a Docker container of Rancher is prior to 1.6.25,
2.0.9, or 2.1.3 and, thus, is affected by a proxy request handling
flaw contained in Kubernetes.

A remote, unauthenticated attacker may be able to leverage API calls
to escalate privileges via proxy request handling vulnerability.

Note that a successful attack requires that an API extension server is
directly accessible from the Kubernetes API server's network or that
a cluster has granted pod exec, attach, port-forward permissions too
loosely.");
  # https://forums.rancher.com/t/rancher-security-advisory-kubernetes-cve-2018-1002105/12598
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abbbe5ed");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.6.25, 2.0.9, 2.1.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1002105");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2018/12/05");
  script_set_attribute(attribute:"patch_publication_date",value:"2018/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/19");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"x-cpe:/a:rancher_labs:rancher");
  script_set_attribute(attribute:"potential_vulnerability",value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rancher_local_detection.nbin");
  script_require_keys("installed_sw/Rancher", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "Rancher";

get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::get_app_info(app:app);

constraints = [
  {"fixed_version" : "1.6.25", "fixed_display" : "v1.6.25"},
  {"min_version"   : "2.0.0",  "fixed_version" : "2.0.9", "fixed_display" : "v2.0.9"},
  {"min_version"   : "2.1.0",  "fixed_version" : "2.1.3", "fixed_display" : "v2.1.3"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
