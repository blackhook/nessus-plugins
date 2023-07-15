#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138901);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-1258", "CVE-2018-8014", "CVE-2018-11776");
  script_bugtraq_id(
    104203,
    104222,
    104530,
    105125,
    105538
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"MySQL Enterprise Monitor 3.4.x < 3.4.10 / 4.x < 4.0.7 / 8.x < 8.0.3  Multiple Vulnerabilities (Oct 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"MySQL Enterprise Monitor running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor running on the remote host is affected by the
following vulnerabilities in its subcomponents:

  - Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when
    alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results
    are used with no namespace and in same time, its upper package have no or wildcard namespace and similar
    to results, same possibility when using url tag which doesn't have value and action set and in same time,
    its upper package have no or wildcard namespace. (CVE-2018-11776)

  - The defaults settings for the CORS filter provided in Apache Tomcat 9.0.0.M1 to 9.0.8, 8.5.0 to 8.5.31,
    8.0.0.RC1 to 8.0.52, 7.0.41 to 7.0.88 are insecure and enable 'supportsCredentials' for all origins. It
    is expected that users of the CORS filter will have configured it appropriately for their environment
    rather than using it in the default configuration. Therefore, it is expected that most users will not be
    impacted by this issue. (CVE-2018-8014)

  - Spring Framework version 5.0.5 when used in combination with any versions of Spring Security contains an
    authorization bypass when using method security. An unauthorized malicious user can gain unauthorized
    access to methods that should be restricted. (CVE-2018-1258)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2018.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 3.4.10, 4.0.7, 8.0.3 or later as referenced in the Oracle security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11776");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8014");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts 2 Multiple Tags Result Namespace Handling RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 Namespace Redirect OGNL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");
  script_require_ports("Services/www", 18443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

app  = 'MySQL Enterprise Monitor';
port = get_http_port(default:18443);

app_info = vcf::get_app_info(app:app, port:port, webapp:true);

constraints = [
  {'min_version' : '3.4', 'fixed_version' : '3.4.10'},
  {'min_version' : '4.0', 'fixed_version' : '4.0.7'},
  {'min_version' : '8.0', 'fixed_version' : '8.0.3'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

