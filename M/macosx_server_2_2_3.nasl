#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77757);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/14  1:59:36");

  script_cve_id("CVE-2014-4424");
  script_bugtraq_id(69918);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-09-17-6");

  script_name(english:"Mac OS X : OS X Server < 2.2.3 Wiki SQL Injection");
  script_summary(english:"Checks the OS X Server version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing a security update for OS X Server.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.8 host has a version of OS X Server installe
that is prior to 2.2.3. It is, therefore, affected by a SQL injection
vulnerability in the Wiki Server component due to improper validation
of user-supplied input. A remote attacker can exploit this to inject
or manipulate SQL queries on the back-end database.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6449");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X Server version 2.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.8([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.8");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "2.2.3";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
