#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100872);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-9523");
  script_bugtraq_id(99016);

  script_name(english:"Sophos Web Appliance < 4.3.2 FTP Redirect Page Reflected XSS");
  script_summary(english:"Checks the build number of Sophos Web Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
reflected cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Sophos Web
Appliance software running on the remote host is prior to 4.3.2. It
is, therefore, affected by a reflected cross-site scripting (XSS)
vulnerability in the FTP redirect page (ftp_redirect.php) due to
improper validation of user-supplied input. An unauthenticated,
remote attacker can exploit this, via a specially crafted request, to
execute arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://swa.sophos.com/rn/swa/concepts/ReleaseNotes_4.3.2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sophos Web Appliance version 4.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9523");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:web_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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
  { "fixed_version" : "4.3.2" }
];

vcf::check_version_and_report(severity:SECURITY_WARNING, constraints:constraints, app_info:app_info, flags:{xss:true});
