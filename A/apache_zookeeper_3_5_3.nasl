#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125634);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-5017", "CVE-2017-5637");
  script_bugtraq_id(93044, 98814);
  script_xref(name:"IAVB", value:"2019-B-0041");

  script_name(english:"Apache ZooKeeper 3.4.0 < 3.4.10 / 3.5.x < 3.5.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache ZooKeeper server is 
  affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ZooKeeper listening on the remote host is prior
to 3.4.10 or 3.5.x prior to 3.5.3. It is, therefore, affected by multiple
vulnerabilities:

  - A buffer overflow vulnerability in the C cli shell. Using 
    the 'cmd:' batch mode syntax allows attackers to have an 
    unspecified impact via a long command string. 
    (CVE-2016-5017)

  - A denial of service (DoS) vulnerability exists in due to two
    four letter word commands which cause CPU spikes on ZooKeeper
    server. An unauthenticated, remote attacker can exploit this 
    issue to cause the application to stop responding. 
    (CVE-2017-5637)");
  script_set_attribute(attribute:"see_also", value:"https://zookeeper.apache.org/security.html");
  script_set_attribute(attribute:"solution", value:
"Update to Apache ZooKeeper 3.4.10 or 3.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5017");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:zookeeper");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_zookeeper_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/zookeeper", 2181);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");

port = get_service(svc:"zookeeper", default:2181, exit_on_fail:TRUE);
app_info = vcf::get_app_info(app:"Apache Zookeeper", port:port, service:TRUE);

# Paranoid because patch exists unrelated to version
if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { "fixed_version" : "3.4.10"},
  { "min_version" : "3.5.0", "fixed_version" : "3.5.3" }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
