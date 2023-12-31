#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70025);
  script_version("1.7");
  script_cvs_date("Date: 2018/07/12 19:01:15");

  script_cve_id("CVE-2013-5649");
  script_bugtraq_id(62353);

  script_name(english:"Juniper Junos Pulse Secure Access Service IVE OS (SSL VPN) Multiple XSS (JSA10589)");
  script_summary(english:"Checks OS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Juniper Junos
Pulse Secure Access Service IVE OS running on the remote host is
affected by multiple unspecified cross-site scripting vulnerabilities
that are present on the login and support pages hosted on the device's
web server. 

An attacker could exploit these issues by tricking a user into
requesting a malicious URL, resulting in arbitrary script code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10589");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Juniper Junos Pulse Secure Access Service IVE OS version
7.1r15 / 7.2r11 / 7.3r6 / 7.4r3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:"^([\d.]+)([Rr](\d+))?");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

release = match[1];
build = 0;
if (!isnull(match[2])) build = int(match[3]);

if (release == '7.1' && build < 15)
  fix = '7.1R15';
else if (release == '7.2' && build < 11)
  fix = '7.2R11';
else if (release == '7.3' && build < 6)
  fix = '7.3R6';
else if (release == '7.4' && build < 3)
  fix = '7.4R3';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'IVE OS', version);

set_kb_item(name:'www/0/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
