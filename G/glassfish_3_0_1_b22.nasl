#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(128523);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2017-1000029", "CVE-2017-1000030");

  script_name(english:"Oracle GlassFish Server < 3.0.1.22 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle GlassFish Server running on the remote host is prior to 
3.0.1.22. It is, therefore, affected by multiple vulnerabilities:
  - A local file inclusion vulnerability exists in Oracle GlassFish Server due to an insufficent level of user input 
    validation. An unauthenticated, remote attacker may exploit this, by sending crafted HTTP requests, to cause the
    remote GlassFish Server to reference local files other than those it was originally designed to reference 
    (CVE-2019-1000029).

  - An information disclosure vulnerability exists in GlassFish Server's java key store component. An unauthenticated, 
    remote attacker can exploit this to disclose potentially sensitive information (CVE-2019-1000030).");
  # https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=18784
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d15fdc0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GlassFish Server version 3.0.1.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000030");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");

  exit(0);
}

include('audit.inc');
include('glassfish.inc');

port = get_glassfish_port(default:8080);

ver = get_kb_item_or_exit('www/' + port + '/glassfish/version');
banner = get_kb_item_or_exit('www/' + port + '/glassfish/source');
pristine = get_kb_item_or_exit('www/' + port + '/glassfish/version/pristine');
fix = '3.0.1.22';

if (empty_or_null(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_LISTEN_NOT_VULN, 'Oracle GlassFish', port, pristine);

report =
  '\n  Version source    : ' + banner +
  '\n  Installed version : ' + pristine +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
