#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103531);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-10978", "CVE-2017-10979");
  script_bugtraq_id(99893, 99901);
  script_xref(name:"APPLE-SA", value:"HT208102");

  script_name(english:"macOS : macOS Server < 5.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the macOS Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update for macOS Server.");
  script_set_attribute(attribute:"description", value:
"The version of macOS Server (formerly known as Mac OS X Server)
installed on the remote host is prior to 5.4. It is, therefore,
affected by the multiple Buffer Overflow DoS vulnerabilities in 
FreeRADIUS");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208102");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS Server version 5.4 or later. Note that macOS Server
version 5.4 is available only for macOS 10.12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10979");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "macOS");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "5.4";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS Server", version);
