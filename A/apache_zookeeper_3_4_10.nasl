#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110266);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-8012");
  script_bugtraq_id(104253);

  script_name(english:"Apache Zookeeper x < 3.4.10 / 3.5.x < 3.5.4 Missing Authentication Remote Quorum Joining Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Zookeeper server is prone to a quorum joining attack.");
  script_set_attribute(attribute:"description", value:
"The instance of Apache Zookeeper listening on the remote host is
either running a version that does not support quorum authentication or
has not been configured to use quorum authentication. This may allow a
remote attacker to join a cluster quorum and begin propagating
counterfeit changes to the leader.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2018/q2/132");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/ZOOKEEPER-1045");
  script_set_attribute(attribute:"solution", value:
"Update to Apache Zookeeper 3.4.10 or 3.5.4 or later and enable
Quorum Peer mutual authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:zookeeper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_zookeeper_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/zookeeper", 2181);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Apache Zookeeper";
port = get_service(svc:"zookeeper", default:2181, exit_on_fail:TRUE);

if (get_install_count(app_name:app_name) > 0)
{
  install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
  version = install.version;
}
else
  version = get_kb_item_or_exit("zookeeper/" + port + "/version");

if (version =~ "^3\.5\.")
  fix = "3.5.4";
else
  fix = "3.4.10";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
}
else if (install.config)
{
  conf_arr = {};
  foreach line (split(install.config, sep:'\n', keep:FALSE))
  {
    match = pregmatch(pattern:"^([^#]+?)=([^\s]*)", string:line);
    if (match && match[1] && match[2])
      conf_arr[tolower(match[1])] = tolower(match[2]);
  }
  if (conf_arr['quorum.auth.enablesasl'] != 'true' ||
      conf_arr['quorum.auth.learnerrequiresasl'] != 'true' ||
      conf_arr['quorum.auth.serverrequiresasl'] != 'true')
  {
    report =
      '\n  The Apache Zookeeper installation detected on port '+ port + ' has not' +
      '\n  been configured for quorum authentication. Please ensure the' +
      '\n  following lines are present in the configuration:' +
      '\n    quorum.auth.enableSasl=true' +
      '\n    quorum.auth.learnerRequireSasl=true' +
      '\n    quorum.auth.serverRequireSasl=true' +
      '\n';
  }
}

if(report)
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
else
  audit(AUDIT_LISTEN_NOT_VULN, "Apache Zookeeper", port, version);
