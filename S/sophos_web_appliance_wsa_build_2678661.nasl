#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99237);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2017-6182",
    "CVE-2017-6183",
    "CVE-2017-6184",
    "CVE-2017-6412"
  );
  script_bugtraq_id(97261);

  script_name(english:"Sophos Web Appliance < 4.3.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number of Sophos Web Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported build number, the Sophos Web Appliance
running on the remote host is prior to 4.3.1.2. It is, therefore,
affected by following vulnerabilities :

  - A remote command injection vulnerability exists due to a
    failure in certain functions to properly sanitize input
    upon submission to reports. An authenticated, remote
    attacker can exploit this to inject arbitrary commands.
    (CVE-2017-6182)

  - A remote command injection vulnerability exists due to
    improper handling of parameters in the active directory
    configuration. An authenticated, remote attacker can
    exploit this to inject arbitrary commands.
    (CVE-2017-6183)

  - A remote command injection vulnerability exists due to a
    failure to properly sanitize input passed via the
    'token' parameter upon submission to reports. An
    authenticated, remote attacker can exploit this to
    inject arbitrary commands. (CVE-2017-6184)

  - An authentication bypass vulnerability exists due to the
    use of static session IDs. An unauthenticated, remote 
    attacker can exploit this to bypass authentication.
    (CVE-2017-6412)

  - A remote command injection vulnerability exists due to a
    failure to properly sanitize unspecified HTTP request
    parameters upon submission to reports. An
    authenticated, remote attacker can exploit this to
    execute arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"http://swa.sophos.com/rn/swa/concepts/ReleaseNotes_4.3.1.2.html");
  # https://community.sophos.com/products/web-appliance/b/blog/posts/release-of-swa-v4-3-1-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10940469");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sophos Web Appliance version 4.3.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6182");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Sophos Web Protection Appliance Reports RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:web_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sophos_web_protection_detect.nasl");
  script_require_keys("installed_sw/sophos_web_protection", "Settings/ParanoidReport");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# WSA_BUILD 2678661 -> v4.3.1.2 mapping is only seen in
# virtual appliance. The WSA_BUILD-version mapping is not
# observed in physical appliance.   
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'sophos_web_protection';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:443);
install = get_single_install(app_name:app, port:port);

build = install['WSA_BUILD'];
if(isnull(build))
  exit(1, 'Failed to get the Sophos Web Appliance WSA_BUILD number.');

dir = install['dir'];
url = build_url(qs:dir, port:port);

fix = 2678661; # v4.3.1.2
if (build < fix)
{
    report =
      '\n  URL                  : ' + url +
      '\n  Installed WSA_BUILD  : ' + build +
      '\n  Fixed WSA_BUILD      : ' + fix + ' (v4.3.1.2)\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else 
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Sophos Web Appliance', url);
}
