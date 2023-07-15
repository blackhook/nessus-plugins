#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0697 and 
# CentOS Errata and Security Advisory 2010:0697 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49261);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3069");
  script_bugtraq_id(43212);
  script_xref(name:"RHSA", value:"2010:0697");

  script_name(english:"CentOS 3 / 4 / 5 : samba (CESA-2010:0697)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 3, 4, and 5, and Red Hat
Enterprise Linux 4.7, 5.3, and 5.4 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

A missing array boundary checking flaw was found in the way Samba
parsed the binary representation of Windows security identifiers
(SIDs). A malicious client could send a specially crafted SMB request
to the Samba server, resulting in arbitrary code execution with the
privileges of the Samba server (smbd). (CVE-2010-3069)

For Red Hat Enterprise Linux 4, this update also fixes the following
bug :

* Previously, the restorecon utility was required during the
installation of the samba-common package. As a result, attempting to
update samba without this utility installed may have failed with the
following error :

/var/tmp/rpm-tmp.[xxxxx]: line 7: restorecon: command not found

With this update, the utility is only used when it is already present
on the system, and the package is now always updated as expected.
(BZ#629602)

Users of Samba are advised to upgrade to these updated packages, which
correct these issues. After installing this update, the smb service
will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f42c48d7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016997.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af18a145"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016998.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0b8192c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/016999.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42a22505"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/017006.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68832905"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-September/017007.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf995d63"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-client-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-client-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-common-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-common-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-swat-3.0.9-1.3E.18")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-swat-3.0.9-1.3E.18")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-client-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-client-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-common-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-common-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-swat-3.0.33-0.19.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-swat-3.0.33-0.19.el4_8.3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libsmbclient-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libsmbclient-devel-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-client-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-common-3.0.33-3.29.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-swat-3.0.33-3.29.el5_5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
}
