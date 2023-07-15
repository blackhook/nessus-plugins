#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1241 and 
# CentOS Errata and Security Advisory 2011:1241 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56273);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1833", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1837", "CVE-2011-3145");
  script_bugtraq_id(49108, 49287);
  script_xref(name:"RHSA", value:"2011:1241");

  script_name(english:"CentOS 5 : ecryptfs-utils (CESA-2011:1241)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ecryptfs-utils packages that fix several security issues are
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

eCryptfs is a stacked, cryptographic file system. It is transparent to
the underlying file system and provides per-file granularity. eCryptfs
is released as a Technology Preview for Red Hat Enterprise Linux 5 and
6.

The setuid mount.ecryptfs_private utility allows users to mount an
eCryptfs file system. This utility can only be run by users in the
'ecryptfs' group.

A race condition flaw was found in the way mount.ecryptfs_private
checked the permissions of a requested mount point when mounting an
encrypted file system. A local attacker could possibly use this flaw
to escalate their privileges by mounting over an arbitrary directory.
(CVE-2011-1831)

A race condition flaw in umount.ecryptfs_private could allow a local
attacker to unmount an arbitrary file system. (CVE-2011-1832)

It was found that mount.ecryptfs_private did not handle certain errors
correctly when updating the mtab (mounted file systems table) file,
allowing a local attacker to corrupt the mtab file and possibly
unmount an arbitrary file system. (CVE-2011-1834)

An insecure temporary file use flaw was found in the
ecryptfs-setup-private script. A local attacker could use this script
to insert their own key that will subsequently be used by a new user,
possibly giving the attacker access to the user's encrypted data if
existing file permissions allow access. (CVE-2011-1835)

A race condition flaw in mount.ecryptfs_private could allow a local
attacker to overwrite arbitrary files. (CVE-2011-1837)

A race condition flaw in the way temporary files were accessed in
mount.ecryptfs_private could allow a malicious, local user to make
arbitrary modifications to the mtab file. (CVE-2011-3145)

A race condition flaw was found in the way mount.ecryptfs_private
checked the permissions of the directory to mount. A local attacker
could use this flaw to mount (and then access) a directory they would
otherwise not have access to. Note: The fix for this issue is
incomplete until a kernel-space change is made. Future Red Hat
Enterprise Linux 5 and 6 kernel updates will correct this issue.
(CVE-2011-1833)

Red Hat would like to thank the Ubuntu Security Team for reporting
these issues. The Ubuntu Security Team acknowledges Vasiliy Kulikov of
Openwall and Dan Rosenberg as the original reporters of CVE-2011-1831,
CVE-2011-1832, and CVE-2011-1833; Dan Rosenberg and Marc Deslauriers
as the original reporters of CVE-2011-1834; Marc Deslauriers as the
original reporter of CVE-2011-1835; and Vasiliy Kulikov of Openwall as
the original reporter of CVE-2011-1837.

Users of ecryptfs-utils are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52413165"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017812.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db14ec10"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af9cba0b"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e894d9a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ecryptfs-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ecryptfs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ecryptfs-utils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ecryptfs-utils-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"ecryptfs-utils-75-5.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ecryptfs-utils-devel-75-5.el5_7.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ecryptfs-utils-gui-75-5.el5_7.2")) flag++;


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
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ecryptfs-utils / ecryptfs-utils-devel / ecryptfs-utils-gui");
}
