#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101530);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-8002", "CVE-2017-8003");
  script_bugtraq_id(99487);

  script_name(english:"EMC Data Protection Advisor < 6.4 Multiple Vulnerabilities");
  script_summary(english:"Checks DPA web gui version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to it's self-reported version number, the EMC Data
Protection Advisor running on the remote host is prior to 6.4. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple blind SQL injection vulnerabilities exist due
    to improper sanitization of user-supplied input before
    using it in SQL queries. An authenticated, remote
    attacker can exploit these to inject or manipulate SQL
    queries in the back-end database, resulting in the
    manipulation or disclosure of arbitrary data.
    (CVE-2017-8002)

  - An information disclosure vulnerability exists due to a
    flaw that allows traversing outside of a restricted
    path. An authenticated, remote attacker can exploit
    this, via a specially crafted request, to disclose
    arbitrary files. (CVE-2017-8003)");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Jul/12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Data Protection Advisor version 6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8003");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:data_protection_advisor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_dpa_web_detect.nasl");
  script_require_keys("installed_sw/emc_dpa");
  script_require_ports("Services/www", 80, 443, 9002);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "emc_dpa";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9002);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "fixed_version":"6.4" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{sqli:TRUE}
);
