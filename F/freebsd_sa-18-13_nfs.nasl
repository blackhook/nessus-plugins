#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119307);
  script_version("1.2");
  script_cvs_date("Date: 2018/12/21 11:57:21");

  script_cve_id("CVE-2018-17157", "CVE-2018-17158", "CVE-2018-17159");

  script_name(english:"FreeBSD < 11.2-RELEASE-p5 Multiple vulnerabilities in NFS server code (FreeBSD-SA-18:03.nfs)");
  script_summary(english:"Checks for the version of the FreeBSD kernel.");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The version of the FreeBSD kernel running on the remote host is prior
to 11.2-RELEASE-p5. It is, therefore, affected by multiple
vulnerabilities in the Network File System (NFS) server code.");
  # https://www.freebsd.org/security/advisories/FreeBSD-SA-18:13.nfs.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74abcc6f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate FreeBSD version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17157");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release =~ "^FreeBSD-([0-9]|1[01]\.[0-3])($|[^0-9])")
  fix = "FreeBSD-11.2_5";

if (isnull(fix) || pkg_cmp(pkg:release, reference:fix) >= 0)
  audit(AUDIT_HOST_NOT, "affected");

report =
  '\n  Installed version : ' + release +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
