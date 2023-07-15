#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100789);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-9681",
    "CVE-2016-10082",
    "CVE-2017-5474",
    "CVE-2017-5475",
    "CVE-2017-5476"
  );
  script_bugtraq_id(
    95095,
    95165,
    95652,
    95656,
    95659
  );

  script_name(english:"Serendipity < 2.1.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Serendipity running on the
remote host is prior to 2.1.1. It is, therefore, affected by multiple
vulnerabilities :

  - A stored cross-site scripting (XSS) vulnerability exists
    in the templates/2k11/admin/category.inc.tpl script due
    to improper validation of the category and directory
    names before returning the input to users. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-9681)

  - A local file inclusion flaw exists in the
    include/functions_installer.inc.php script due to
    improper sanitization of user supplied-input to the
    'dbType' POST parameter. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request that uses absolute paths, to include files on
    the targeted host, resulting in the disclosure of file
    contents or the possible execution of files as PHP
    scripts. (CVE-2016-10082)

  - A cross-site redirection vulnerability exists in the
    comment.php script due to improper validation of the
    HTTP referer header. An unauthenticated, remote attacker
    can exploit this, via a specially crafted link, to
    redirect an unsuspecting user from a legitimate website
    to a website of the attacker's choosing, which could
    then be used to conduct further attacks.
    (CVE-2017-5474)

  - A cross-site request forgery (XSRF) vulnerability exists
    in comment.php due to not requiring multiple steps,
    explicit confirmation, or a unique token when performing
    certain sensitive actions. An unauthenticated, remote
    attacker can exploit this, by convincing a user to
    follow a specially crafted link, to cause the deletion
    of arbitrary comments. (CVE-2017-5475)

  - A cross-site request forgery (XSRF) vulnerability exists
    in unspecified scripts due to not requiring multiple
    steps, explicit confirmation, or a unique token when
    performing certain sensitive actions. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a specially crafted link, to
    cause the installation of event or sidebar plugins.
    (CVE-2017-5476)");
  script_set_attribute(attribute:"see_also", value:"https://github.com/s9y/Serendipity/issues/433");
  script_set_attribute(attribute:"see_also", value:"https://github.com/s9y/Serendipity/issues/439");
  # https://github.com/s9y/Serendipity/commit/e2a665e13b7de82a71c9bbb77575d15131b722be
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98bd3703");
  # https://github.com/s9y/Serendipity/commit/6285933470bab2923e4573b5d54ba9a32629b0cd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93a3f574");
  script_set_attribute(attribute:"see_also", value:"https://blog.s9y.org/archives/274-Serendipity-2.1.1-released.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Serendipity version 2.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:s9y:serendipity");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("serendipity_detect.nasl");
  script_require_keys("www/serendipity");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

app = 'serendipity';
fix = '2.1.1';

get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
    {"max_version" : "2.1.0", "fixed_version" : "2.1.1"  }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE,xsrf:TRUE});

