#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0044 and 
# CentOS Errata and Security Advisory 2007:0044 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24289);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0494");
  script_bugtraq_id(22231);
  script_xref(name:"RHSA", value:"2007:0044");

  script_name(english:"CentOS 3 / 4 : bind (CESA-2007:0044)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix a security issue and a bug are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ISC BIND (Berkeley Internet Name Domain) is an implementation of the
DNS (Domain Name System) protocols.

A flaw was found in the way BIND processed certain DNS query
responses. On servers that had enabled DNSSEC validation, this could
allow an remote attacker to cause a denial of service. (CVE-2007-0494)

For users of Red Hat Enterprise Linux 3, the previous BIND update
caused an incompatible change to the default configuration that
resulted in rndc not sharing the key with the named daemon. This
update corrects this bug and restores the behavior prior to that
update.

Updating the bind package in Red Hat Enterprise Linux 3 could result
in nonfunctional configuration in case the bind-libs package was not
updated. This update corrects this bug by adding the correct
dependency on bind-libs.

Users of BIND are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013504.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05e45fdf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013505.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abbcdfe7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013507.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a70ef5e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013508.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6d159ca"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013511.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5843063a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013513.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f66329a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"bind-9.2.4-20.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-chroot-9.2.4-20.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-devel-9.2.4-20.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-libs-9.2.4-20.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"bind-utils-9.2.4-20.EL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"bind-9.2.4-24.EL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bind-chroot-9.2.4-24.EL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bind-devel-9.2.4-24.EL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bind-libs-9.2.4-24.EL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"bind-utils-9.2.4-24.EL4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libs / bind-utils");
}
