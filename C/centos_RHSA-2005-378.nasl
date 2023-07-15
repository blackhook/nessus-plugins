#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:378 and 
# CentOS Errata and Security Advisory 2005:378 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21815);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1111");
  script_bugtraq_id(13159);
  script_xref(name:"RHSA", value:"2005:378");

  script_name(english:"CentOS 3 / 4 : cpio (CESA-2005:378)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cpio package that fixes multiple issues is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

GNU cpio copies files into or out of a cpio or tar archive.

A race condition bug was found in cpio. It is possible for a local
malicious user to modify the permissions of a local file if they have
write access to a directory in which a cpio archive is being
extracted. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1111 to this issue.

Additionally, this update adds cpio support for archives larger than
2GB. However, the size of individual files within an archive is
limited to 4GB.

All users of cpio are advised to upgrade to this updated package,
which contains backported fixes for these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011938.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d58a37f6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011940.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0fd3f45c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011943.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da78775d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011944.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bffea584"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011951.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?981c5aef"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011952.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?727e62d2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0608d7ad"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-July/011954.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a539f070"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cpio package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cpio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (rpm_check(release:"CentOS-3", reference:"cpio-2.5-4.RHEL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"cpio-2.5-8.RHEL4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpio");
}
