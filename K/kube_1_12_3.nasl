#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119327);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-1002105");

  script_name(english:"Kubernetes 1.x < 1.10.11 / 1.11.x < 1.11.5 / 1.12.x < 1.12.3 API Server Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Kubernetes installed on the remote host is version
1.x prior to 1.10.11, 1.11.x prior to 1.11.5, or 1.12.x prior to
1.12.3, and thus, is affected by a remote, unauthenticated privilege
escalation vulnerability.

Note that a successful attack requires that an API extension server is
directly accessible from the Kubernetes API server's network or that
a cluster has granted pod exec, attach, portforward permissions too
loosely.");
  # https://groups.google.com/forum/#!topic/kubernetes-announce/GVllWCg6L88
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24a13549");
  # https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.10.md/#v11011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98c83f19");
  # https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.11.md/#v1115
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec479a99");
  # https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.12.md/#v1123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1cc1943");
  script_set_attribute(attribute:"see_also", value:"https://github.com/kubernetes/kubernetes/issues/71411");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kubernetes 1.10.11, 1.11.5, 1.12.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1002105");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kubernetes:kubernetes");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:kubernetes");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kube_detect.nbin");
  script_require_keys("installed_sw/Kubernetes", "Settings/ParanoidReport");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Kubernetes";

app_info = vcf::get_app_info(app:app_name);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version": "1.0.0",  "fixed_version" : "1.10.11" },
  { "min_version": "1.11.0", "fixed_version" : "1.11.5"  },
  { "min_version": "1.12.0", "fixed_version" : "1.12.3"  },
  { "min_version": "1.13.0-alpha.0", "fixed_version" : "1.13.0-rc.1"  }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
