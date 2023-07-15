#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138903);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-1559");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"MySQL Enterprise Monitor 4.x < 4.0.9 / 8.x < 8.0.16 Padding Oracle (Apr 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"MySQL Enterprise Monitor running on the remote host is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL used in the remote host's detected MySQL Enterprise Monitor version is affected by a
vulnerability. If an application encounters a fatal protocol error and then calls SSL_shutdown() twice (once to send a
close_notify, and once to receive one) then OpenSSL can respond differently to the calling application if a 0 byte
record is received with invalid padding compared to if a 0 byte record is received with an invalid MAC. If the
application then behaves differently based on that in a way that is detectable to the remote peer, then this amounts to
a padding oracle that could be used to decrypt data. In order for this to be exploitable 'non-stitched' ciphersuites
must be in use. Stitched ciphersuites are optimised implementations of certain commonly used ciphersuites. Also the
application must call SSL_shutdown() twice even if a protocol error has occurred (applications should not do this but
some do anyway). 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2019.html#AppendixMSQL");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL Enterprise Monitor version 4.0.9, 8.0.16 or later as referenced in the Oracle security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
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
  { 'min_version' : '4.0', 'fixed_version' : '4.0.9' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.16' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
