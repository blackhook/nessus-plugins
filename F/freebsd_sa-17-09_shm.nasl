#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104971);
  script_version("1.8");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-2017-1087");
  script_bugtraq_id(101867);

  script_name(english:"FreeBSD 10.3 / 10.4 : shm Insecure Memory Vulnerability (FreeBSD-SA-17:09.shm)");
  script_summary(english:"Checks for the version of the FreeBSD kernel.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The version of the FreeBSD kernel running on the remote host is prior
to 10.3-RELEASE-p24, or 10.4 prior to 10.4-RELEASE-p3. It is,
therefore, affected by a potential information disclosure
vulnerabilities in shm. An authenticated, remote attacker can exploit
this issue by accessing the shared memory space in a jail to access
and modify shared memory spaces in other jails. This can be used to
target processes such as squid, and cause denials of service, or
privilege escalations.

Only systems running jails with local users are affected.");
  # https://www.freebsd.org/security/advisories/FreeBSD-SA-17:09.shm.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e9dd83e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate FreeBSD version.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1087");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

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

if (release =~ "^FreeBSD-([0-9]|10\.[0-3])($|[^0-9])")
  fix = "FreeBSD-10.3_24";
else if (release =~ "^FreeBSD-10\.4($|[^0-9])")
  fix = "FreeBSD-10.4_3";

if (isnull(fix) || pkg_cmp(pkg:release, reference:fix) >= 0)
  audit(AUDIT_HOST_NOT, "affected");

report =
  '\n  Installed version : ' + release +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
