#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1219 and 
# CentOS Errata and Security Advisory 2011:1219 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55997);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0547", "CVE-2010-0787", "CVE-2011-1678", "CVE-2011-2522", "CVE-2011-2694", "CVE-2011-3585");
  script_bugtraq_id(37992);
  script_xref(name:"RHSA", value:"2011:1219");

  script_name(english:"CentOS 4 / 5 : samba (CESA-2011:1219)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

A cross-site scripting (XSS) flaw was found in the password change
page of the Samba Web Administration Tool (SWAT). If a remote attacker
could trick a user, who was logged into the SWAT interface, into
visiting a specially crafted URL, it would lead to arbitrary web
script execution in the context of the user's SWAT session.
(CVE-2011-2694)

It was found that SWAT web pages did not protect against Cross-Site
Request Forgery (CSRF) attacks. If a remote attacker could trick a
user, who was logged into the SWAT interface, into visiting a
specially crafted URL, the attacker could perform Samba configuration
changes with the privileges of the logged in user. (CVE-2011-2522)

A race condition flaw was found in the way the mount.cifs tool mounted
CIFS (Common Internet File System) shares. If mount.cifs had the
setuid bit set, a local attacker could conduct a symbolic link attack
to trick mount.cifs into mounting a share over an arbitrary directory
they were otherwise not allowed to mount to, possibly allowing them to
escalate their privileges. (CVE-2010-0787)

It was found that the mount.cifs tool did not properly handle share or
directory names containing a newline character. If mount.cifs had the
setuid bit set, a local attacker could corrupt the mtab (mounted file
systems table) file via a specially crafted CIFS share mount request.
(CVE-2010-0547)

It was found that the mount.cifs tool did not handle certain errors
correctly when updating the mtab file. If mount.cifs had the setuid
bit set, a local attacker could corrupt the mtab file by setting a
small file size limit before running mount.cifs. (CVE-2011-1678)

Note: mount.cifs from the samba packages distributed by Red Hat does
not have the setuid bit set. We recommend that administrators do not
manually set the setuid bit for mount.cifs.

Red Hat would like to thank the Samba project for reporting
CVE-2011-2694 and CVE-2011-2522; the Debian Security Team for
reporting CVE-2010-0787; and Dan Rosenberg for reporting
CVE-2011-1678. Upstream acknowledges Nobuhiro Tsuji of NTT DATA
Security Corporation as the original reporter of CVE-2011-2694;
Yoshihiro Ishikawa of LAC Co., Ltd. as the original reporter of
CVE-2011-2522; and the Debian Security Team acknowledges Ronald
Volgers as the original reporter of CVE-2010-0787.

Users of Samba are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the smb service will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017708.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6da8e78"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017709.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8d50dd8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017966.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe52cf92"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017967.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74ab0647"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000136.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29bfd921"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000137.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b1868b9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/30");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-client-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-client-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-common-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-common-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-swat-3.0.33-0.34.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-swat-3.0.33-0.34.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libsmbclient-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libsmbclient-devel-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-client-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-common-3.0.33-3.29.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-swat-3.0.33-3.29.el5_7.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
}
