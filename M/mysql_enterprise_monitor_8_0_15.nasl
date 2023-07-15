#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138904);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-15756");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"MySQL Enterprise Monitor 4.x < 4.0.10 / 8.x < 8.0.15 DoS (Jul 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"MySQL Enterprise Monitor running on the remote host is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in MySQL Enterprise Monitor due the use of a vulnerable Spring Framework
version. Spring Framework, version 5.1, versions 5.0.x prior to 5.0.10, versions 4.3.x prior to 4.3.20, and older
unsupported versions on the 4.2.x branch provide support for range requests when serving static resources through the
ResourceHttpRequestHandler, or starting in 5.0 when an annotated controller returns an
org.springframework.core.io.Resource. A malicious user (or attacker) can add a range header with a high number of
ranges, or with wide ranges that overlap, or both, to cause a DoS. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2019.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 4.0.10, 8.0.15 or later as referenced in the Oracle security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15756");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version' : '4.0', 'fixed_version' : '4.0.10'},
  {'min_version' : '8.0', 'fixed_version' : '8.0.15'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
