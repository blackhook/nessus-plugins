#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100720);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id(
    "CVE-2017-1178",
    "CVE-2017-1179",
    "CVE-2017-1196",
    "CVE-2017-1197"
  );
  script_bugtraq_id(98909, 98910, 98911);
  script_xref(name:"IAVB", value:"2017-B-0063");

  script_name(english:"IBM BigFix Compliance 1.9.70 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM BigFix Compliance.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote web
server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of IBM BigFix
Compliance running on the remote web server is 1.9.70. It is,
therefore, affected by multiple vulnerabilities :

  - A stored cross-site scripting (XSS) vulnerability exists
    in the Analytics component in the Web UI due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2017-1178)

  - An information disclosure vulnerability exists in the
    Analytics component due to the use of outdated
    encryption algorithms. A man-in-the-middle (MitM)
    attacker can exploit this to disclose sensitive
    information. (CVE-2017-1179)

  - An information disclosure vulnerability exists in the
    Analytics component due to a weak default password
    policy. An unauthenticated, remote attacker can exploit
    this, via a brute-force attack, to disclose user account
    credentials. (CVE-2017-1196)

  - A security weakness exists in the Analytics component
    due to a failure to securely lockout accounts after
    multiple failed authentication attempts. An
    unauthenticated, remote attacker can exploit this to
    perform brute-force attacks. (CVE-2017-1197)");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22004161");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22004164");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22004168");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22004170");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Compliance version 1.9.79 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1197");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:bigfix_compliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_bigfix_compliance_detect.nbin");
  script_require_keys("installed_sw/IBM BigFix Compliance");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:"IBM BigFix Compliance", port:port, webapp:true);

constraints = [
  { "min_version" : "1.9.70", "max_version" : "1.9.70", "fixed_version" : "1.9.79" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{"xss":TRUE});
