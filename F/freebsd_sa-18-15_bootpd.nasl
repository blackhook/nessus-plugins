#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126754);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/21");

  script_cve_id("CVE-2018-17161");
  script_bugtraq_id(106292);

  script_name(english:"FreeBSD 11.x < 11.2-RELEASE-p7 / 12.x < 12.0-RELEASE-p1 bootpd stack buffer overflow");
  script_summary(english:"Checks for the version of the FreeBSD kernel.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The version of the FreeBSD kernel running on the remote host is 11.x prior to 11.2-RELEASE-p7 or 12.x prior to
12.0-RELEASE-p1. It is, therefore, affected by a stack buffer overflow vulnerability in bootpd. Insufficient validation
of network-provided data in bootpd may make it possible for a malicious attacker to craft a bootp packet which could
cause a stack buffer overflow. It is possible that the buffer overflow could lead to a Denial of Service or remote code
execution.");
  # https://www.freebsd.org/security/advisories/FreeBSD-SA-18:15.bootpd.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ffd9047");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate FreeBSD version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17161");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("freebsd_package.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/FreeBSD/release");
if (!release) audit(AUDIT_OS_NOT, "FreeBSD");

# Patches are available, require paranoid since it is possible
# to manually patch and have a lower OS level.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = NULL;

if (release =~ "^FreeBSD-11\.[0-2]($|[^0-9])")
  fix = "FreeBSD-11.2_7";
else if (release =~ "^FreeBSD-12\.0($|[^0-9])")
  fix = "FreeBSD-12.0_1";

if (isnull(fix) || pkg_cmp(pkg:release, reference:fix) >= 0)
  audit(AUDIT_HOST_NOT, "affected");

report =
  '\n  Installed version : ' + release +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
