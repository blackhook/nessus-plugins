#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119559);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-2911", "CVE-2018-3152", "CVE-2018-3210");
  script_bugtraq_id(105618);

  script_name(english:"Oracle GlassFish Server 3.1.2.x < 3.1.2.19 (October 2018 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle GlassFish Server
running on the remote host is 3.1.2.x prior to 3.1.2.19. Is is, 
therefore, affected by multiple vulnerabilities:

  - A vulnerability could allow an Attacker with unauthenticated 
    network access to compromise Oracle GlassFish Server. A successful 
    attack would allow the access to critical data including
    creation, deletion or modification on the remote server. This 
    attack requires human interaction. (CVE-2018-2911)
  - An unauthenticated attacker with Network access can compromise 
    Oracle GlassFish Server. An attacker who successfully exploited 
    the vulnerability could cause a hang or a complete DOS of Oracle 
    GlassFish Server. (CVE-2018-3152)
  - An unauthenticated attacker with network access could compromise 
    Oracle GlassFish Server. An attacker who successfully exploited 
    the vulnerability could have read access to Oracle GlassFish 
    Server information. (CVE-2018-3210)");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?705136d8");
  # https://support.oracle.com/epmos/faces/ui/patch/PatchDetail.jspx?_afrLoop=542144881266123&parent=DOCUMENT&patchId=28648149
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28d119b1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GlassFish Server version 3.1.2.19 or later as
referenced in the October 2018 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('audit.inc');
include('glassfish.inc');

# Check for GlassFish
get_kb_item_or_exit('www/glassfish');

port = get_glassfish_port(default:8080);

# Get the version number out of the KB.
ver = get_kb_item_or_exit('www/' + port + '/glassfish/version');
banner = get_kb_item_or_exit("www/" + port + '/glassfish/source');
pristine = get_kb_item_or_exit('www/' + port + '/glassfish/version/pristine');


if (ver =~ "^3\.1\.2")
{
  min = '3.1.2';
  fix = '3.1.2.19';
}

if (!empty_or_null(ver) && ver_compare(minver:min, ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + pristine +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Oracle GlassFish', port, pristine);
