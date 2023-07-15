#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88903);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-8148",
    "CVE-2015-8149",
    "CVE-2015-8150",
    "CVE-2015-8151"
  );
  script_bugtraq_id(
    83268,
    83269,
    83270,
    83271
  );

  script_name(english:"Symantec Encryption Management Server 3.3.2 < 3.3.2 MP12 Multiple Vulnerabilities (SYM16-002)");

  script_set_attribute(attribute:"synopsis", value:
"A security policy management application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Encryption Management Server running on the
remote host is 3.3.2 prior to version 3.3.2 MP12. It is, therefore, 
affected by multiple vulnerabilities :

  - An unspecified flaw in the LDAP service allows a remote
    attacker, via a crafted LDAP request, to gather
    sensitive information about valid administrator accounts
    on the server. (CVE-2015-8148)

  - A denial of service exists in the LDAP service due to a
    failure to properly validate user-supplied input. An
    unauthenticated, remote attacker can exploit this, via
    crafted request packets, to cause corrupted memory block
    headers, leading to a SIGSEGV fault and resulting in a
    service halt. (CVE-2015-8149)

  - An unspecified flaw exists that is related to scheduling
    commands to run via existing batch files, which normally
    run with root privileges. A local attacker can exploit
    this to gain elevated privileges on the server.
    (CVE-2015-8150)

  - A command injection vulnerability exists in the web user
    interface due to a failure to properly sanitize certain
    user-supplied input fields. An authenticated, remote
    attacker can exploit this to run arbitrary commands with
    elevated privileges on the underlying operating system.
    (CVE-2015-8151)");
  # https://support.symantec.com/en_US/article.SYMSA1346.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24f58288");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Encryption Management Server version 3.3.2 MP12 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8150");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_management_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_encryption_server_detect.nbin");
  script_require_keys("LDAP/symantec_encryption_server/detected");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Symantec Encryption Management Server";

get_kb_item_or_exit("LDAP/symantec_encryption_server/detected");

port = get_service(svc:"ldap", default: 389, exit_on_fail:FALSE);

version = get_kb_item_or_exit("LDAP/symantec_encryption_server/" + port + "/version");
build = get_kb_item_or_exit("LDAP/symantec_encryption_server/" + port + "/build");

# Detection plugin places "Unknown" value if it
# happens to fail when looking for build or version
# Note: Even base versions still should have
#       build information associated with them.
if (version =~ "^U|unknown$" || build =~ "^U|unknown$")
  audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Complete the version by appending build number
version = version + '.' + build;

# Check for granularity in this full version number
if (version !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

# 3.3.2 All builds
fix = "3.3.2.21436";
fix_disp = "3.3.2.21436 (3.3.2 MP12)";

if (version =~ "^3\.3\.2\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_disp +
    '\n';
  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
