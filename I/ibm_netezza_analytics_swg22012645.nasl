#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106714);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2013-0340", "CVE-2013-0341");
  script_bugtraq_id(58233);

  script_name(english:"IBM Netezza Analytics Open Source James Clark Expat Multiple Vulnerabilities (swg22012645)");
  script_summary(english:"Checks the IBM Netezza Analytics version.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise data warehousing component installed on the remote
Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Netezza Analytics installed on the remote Linux
host is 1.2.1 - 3.2.1. It is, therefore, affected by multiple
vulnerabilities in the Open Source James Clark Expat component.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22012645");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Netezza Analytics version 3.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0340");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:netezza");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_netezza_platform_software_installed.nbin");
  script_require_keys("installed_sw/IBM Netezza Platform Software");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

app_name = "IBM Netezza Platform Software";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

app_name = "IBM Netezza Analytics";
inza_ver = install["Netezza Analytics version"];

if (inza_ver == UNKNOWN_VER)
  audit(AUDIT_NOT_INST, app_name);

min = "1.2.1";
fix = "3.2.2";

if (ver_compare(ver:inza_ver, fix:min, strict:FALSE) < 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, inza_ver);

if (ver_compare(ver:inza_ver, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Installed version : ' + inza_ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, "IBM Netezza Analytics", inza_ver);
