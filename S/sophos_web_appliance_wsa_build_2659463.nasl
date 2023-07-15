#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100846);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2016-9553", "CVE-2016-9554");
  script_bugtraq_id(95853, 95858);
  script_xref(name:"EDB-ID", value:"41413");
  script_xref(name:"EDB-ID", value:"41414");

  script_name(english:"Sophos Web Appliance < 4.3.1 Multiple Remote Command Injection Vulnerabilities");
  script_summary(english:"Checks the build number of Sophos Web Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
remote command injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Sophos Web
Appliance software running on the remote host is prior to 4.3.1. It
is, therefore, affected by multiple vulnerabilities :

  - A remote command injection vulnerability exists in the
    web administration interface in the
    /controllers/MgrReport.php script when blocking and
    unblocking IP addresses due to improper validation of
    user-supplied input passed to the unblockip' and
    'blockip' parameters. An authenticated, remote attacker
    can exploit this, via a specially crafted request, to
    inject arbitrary shell commands. (CVE-2016-9553)

  - A remote command injection vulnerability exists in the
    web administrative interface in the
    /controllers/MgrDiagnosticTools.php script when
    performing diagnostic tests due to improper validation
    of user-supplied input passed to the url' parameter. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-9554)");
  script_set_attribute(attribute:"see_also", value:"http://swa.sophos.com/rn/swa/concepts/ReleaseNotes_4.3.1.html");
  # https://community.sophos.com/products/web-appliance/b/blog/posts/release-of-swa-version-4-3-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fa2210a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sophos Web Appliance version 4.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:web_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sophos_web_protection_detect.nasl");
  script_require_keys("installed_sw/sophos_web_protection");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = 'sophos_web_protection';
app_info = vcf::get_app_info(app:app, webapp:true, port:443);

constraints = [
  { "fixed_version" : "4.3.1" }
];

vcf::check_version_and_report(severity:SECURITY_HOLE, constraints:constraints, app_info:app_info);
