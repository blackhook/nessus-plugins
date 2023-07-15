
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11499);
 script_version("1.33");
 script_cvs_date("Date: 2018/09/17 21:46:53");

 script_cve_id("CVE-2003-0161");
 script_bugtraq_id(7230);
  script_xref(name:"RHSA", value:"2003:120-01");

 script_name(english: "Sendmail < 8.12.9 NOCHAR Control Value prescan Overflow");
 script_summary(english:"Checks the version of Sendmail.");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server");
 script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number,
may be vulnerable to a remote buffer overflow allowing remote
users to gain root privileges.

Sendmail versions from 5.79 to 8.12.8 are vulnerable.

NOTE: manual patches do not change the version numbers.
Vendors who have released patched versions of Sendmail may still
falsely show a vulnerability.

*** Nessus reports this vulnerability using only the banner of the
*** remote SMTP server. Therefore, this might be a false positive.");
  # http://web.archive.org/web/20031202022838/http://www.sendmail.org/patchps.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91a7a35b");
  script_set_attribute(attribute: "solution", value:
"Upgrade to Sendmail version 8.12.9 or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0161");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "min_version" : "5.79", "fixed_version" : "8.12.9" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
