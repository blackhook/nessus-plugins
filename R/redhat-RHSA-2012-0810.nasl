#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0810. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59586);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-1168", "CVE-2011-2716");
  script_bugtraq_id(48879);
  script_xref(name:"RHSA", value:"2012:0810");

  script_name(english:"RHEL 6 : busybox (RHSA-2012:0810)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated busybox packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

BusyBox provides a single binary that includes versions of a large
number of system commands, including a shell. This can be very useful
for recovering from certain types of system failures, particularly
those involving broken shared libraries.

A buffer underflow flaw was found in the way the uncompress utility of
BusyBox expanded certain archive files compressed using Lempel-Ziv
compression. If a user were tricked into expanding a specially crafted
archive file with uncompress, it could cause BusyBox to crash or,
potentially, execute arbitrary code with the privileges of the user
running BusyBox. (CVE-2006-1168)

The BusyBox DHCP client, udhcpc, did not sufficiently sanitize certain
options provided in DHCP server replies, such as the client hostname.
A malicious DHCP server could send such an option with a specially
crafted value to a DHCP client. If this option's value was saved on
the client system, and then later insecurely evaluated by a process
that assumes the option is trusted, it could lead to arbitrary code
execution with the privileges of that process. Note: udhcpc is not
used on Red Hat Enterprise Linux by default, and no DHCP client script
is provided with the busybox packages. (CVE-2011-2716)

This update also fixes the following bugs :

* Prior to this update, the 'findfs' command did not recognize Btrfs
partitions. As a consequence, an error message could occur when
dumping a core file. This update adds support for recognizing such
partitions so the problem no longer occurs. (BZ#751927)

* If the 'grep' command was used with the '-F' and '-i' options at the
same time, the '-i' option was ignored. As a consequence, the 'grep
-iF' command incorrectly performed a case-sensitive search instead of
an insensitive search. A patch has been applied to ensure that the
combination of the '-F' and '-i' options works as expected.
(BZ#752134)

* Prior to this update, the msh shell did not support the 'set -o
pipefail' command. This update adds support for this command.
(BZ#782018)

* Previously, the msh shell could terminate unexpectedly with a
segmentation fault when attempting to execute an empty command as a
result of variable substitution (for example msh -c
'$nonexistent_variable'). With this update, msh has been modified to
correctly interpret such commands and no longer crashes in this
scenario. (BZ#809092)

* Previously, the msh shell incorrectly executed empty loops. As a
consequence, msh never exited such a loop even if the loop condition
was false, which could cause scripts using the loop to become
unresponsive. With this update, msh has been modified to execute and
exit empty loops correctly, so that hangs no longer occur. (BZ#752132)

All users of busybox are advised to upgrade to these updated packages,
which contain backported patches to fix these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:0810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-2716"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected busybox and / or busybox-petitboot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:busybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:busybox-petitboot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0810";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"busybox-1.15.1-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"busybox-1.15.1-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"busybox-1.15.1-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"busybox-petitboot-1.15.1-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"busybox-petitboot-1.15.1-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"busybox-petitboot-1.15.1-15.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "busybox / busybox-petitboot");
  }
}
