#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0663 and 
# CentOS Errata and Security Advisory 2006:0663 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22338);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-1168");
  script_bugtraq_id(19455);
  script_xref(name:"RHSA", value:"2006:0663");

  script_name(english:"CentOS 3 / 4 : ncompress (CESA-2006:0663)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ncompress packages that address a security issue and fix bugs
are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The ncompress package contains file compression and decompression
utilities, which are compatible with the original UNIX compress
utility (.Z file extensions).

Tavis Ormandy of the Google Security Team discovered a lack of bounds
checking in ncompress. An attacker could create a carefully crafted
file that could execute arbitrary code if uncompressed by a victim.
(CVE-2006-1168)

In addition, two bugs that affected Red Hat Enterprise Linux 4
ncompress packages were fixed :

* The display statistics and compression results in verbose mode were
not shown when operating on zero length files.

* An attempt to compress zero length files resulted in an unexpected
return code.

Users of ncompress are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013219.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f388176"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22f99345"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42303fca"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013235.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?917ce9cf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5d41eb6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-September/013249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a543b4b1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ncompress package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ncompress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"ncompress-4.2.4-39.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"ncompress-4.2.4-43.rhel4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ncompress");
}
