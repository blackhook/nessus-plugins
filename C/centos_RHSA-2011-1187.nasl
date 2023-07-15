#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1187 and 
# CentOS Errata and Security Advisory 2011:1187 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55924);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1929");
  script_bugtraq_id(47930);
  script_xref(name:"RHSA", value:"2011:1187");

  script_name(english:"CentOS 4 / 5 : dovecot (CESA-2011:1187)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dovecot packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Dovecot is an IMAP server for Linux, UNIX, and similar operating
systems, primarily written with security in mind.

A denial of service flaw was found in the way Dovecot handled NULL
characters in certain header names. A mail message with specially
crafted headers could cause the Dovecot child process handling the
target user's connection to crash, blocking them from downloading the
message successfully and possibly leading to the corruption of their
mailbox. (CVE-2011-1929)

Users of dovecot are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing the updated packages, the dovecot service will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017700.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bec230a5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017701.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?450a9ab6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017807.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3258b204"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017808.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72914302"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000198.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81fce7a4"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000199.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a3a0c43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dovecot-0.99.11-10.EL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dovecot-0.99.11-10.EL4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"dovecot-1.0.7-7.el5_7.1")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot");
}
