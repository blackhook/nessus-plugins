#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102917);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/10 16:10:17");

  script_cve_id("CVE-2016-6515");
  script_bugtraq_id(92212);

  script_name(english:"FreeBSD < 10.3-RELEASE-p21 / 11.0 < 11.0-RELEASE-p12 / 11.1 < 11.1-RELEASE-p1 OpenSSH Password Length DoS (FreeBSD-SA-17:06.openssh)");
  script_summary(english:"Checks for the version of the FreeBSD kernel.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The version of the FreeBSD kernel running on the remote host is prior
to 10.3-RELEASE-p21, 11.0 prior to 11.0-RELEASE-p12, or 11.1 prior to
11.1-RELEASE-p1. It, therefore, affected by a flaw in built-in
password authentication in OpenSSH. An unauthenticated, remote
attacker can exploit this issue by sending very long passwords when
PasswordAuthentication is enabled by the system administrator,
resulting in a denial of service condition.

Note that this issue only affects hosts with PasswordAuthentication
enabled in /etc/ssh/sshd_config (the default FreeBSD configuration).

You may workaround this issue by disabling PasswordAuthentication and
restarting sshd.");
  # https://www.freebsd.org/security/advisories/FreeBSD-SA-17:06.openssh.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?beaa28e9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FreeBSD version 10.3-RELEASE-p21 / 11.0-RELEASE-p12 /
11.1-RELEASE-p1 or later. Alternatively, apply the workaround
referenced in the advisory to disable PasswordAuthentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("freebsd_package.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/FreeBSD/release");
if (!release) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);

# Patches are available and ipfilter must be enabled with
# "keep state" or "keep frags" rule options enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = NULL;

if (release =~ "^FreeBSD-([0-9]|10\.[0-3])($|[^0-9])")
  fix = "FreeBSD-10.3_21";
else if (release =~ "^FreeBSD-11\.0($|[^0-9])")
  fix = "FreeBSD-11.0_12";
else if (release =~ "^FreeBSD-11\.1($|[^0-9])")
  fix = "FreeBSD-11.1_1";

if (isnull(fix) || pkg_cmp(pkg:release, reference:fix) >= 0)
  audit(AUDIT_HOST_NOT, "affected");

report =
  '\n  Installed version : ' + release +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
