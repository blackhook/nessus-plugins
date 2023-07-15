#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103113);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2017-12225");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf58392");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170906-prime-lms");

  script_name(english:"Cisco Prime LAN Management Solution Session Fixation Vulnerability");
  script_summary(english:"Checks the Cisco Prime LAN Management Solution (LMS) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Prime LAN Management Solution (LMS) is affected
  by one or more vulnerabilities. Please see the included Cisco BIDs
  and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170906-prime-lms
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cdaabf5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf58392");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
  CSCvf58392.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_lan_management_solution");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_lms_web_detect.nasl");
  script_require_keys("installed_sw/cisco_lms");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"cisco_lms", exit_if_zero:TRUE);

port = get_http_port(default:443);
app = "Cisco Prime LAN Management Solution";

install = get_single_install(
  app_name : "cisco_lms",
  port     : port,
  exit_if_unknown_ver : TRUE
);
version = install["version"];
path = install["path"];
url = build_url(port:port, qs:path);

if (cisco_gen_ver_compare(a:version, b:'4.2(5)') == 0)
{
  report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + "See advisory" +
  '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
