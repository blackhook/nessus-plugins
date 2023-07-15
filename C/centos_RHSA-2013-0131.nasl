#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0131 and 
# CentOS Errata and Security Advisory 2013:0131 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63576);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2473");
  script_bugtraq_id(36080);
  script_xref(name:"RHSA", value:"2013:0131");

  script_name(english:"CentOS 5 : gnome-vfs2 (CESA-2013:0131)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnome-vfs2 packages that fix one security issue and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The gnome-vfs2 packages provide the GNOME Virtual File System, which
is the foundation of the Nautilus file manager. neon is an HTTP and
WebDAV client library embedded in the gnome-vfs2 packages.

A denial of service flaw was found in the neon Extensible Markup
Language (XML) parser. Visiting a malicious DAV server with an
application using gnome-vfs2 (such as Nautilus) could possibly cause
the application to consume an excessive amount of CPU and memory.
(CVE-2009-2473)

This update also fixes the following bugs :

* When extracted from the Uniform Resource Identifier (URI),
gnome-vfs2 returned escaped file paths. If a path, as stored in the
URI, contained non-ASCII characters or ASCII characters which are
parsed as something other than a file path (for example, spaces), the
escaped path was inaccurate. Consequently, files with the described
type of URI could not be processed. With this update, gnome-vfs2
properly unescapes paths that are required for a system call. As a
result, these paths are parsed properly. (BZ#580855)

* In certain cases, the trash info file was populated by foreign
entries, pointing to live data. Emptying the trash caused an
accidental deletion of valuable data. With this update, a workaround
has been applied in order to prevent the deletion. As a result, the
accidental data loss is prevented, however further information is
still gathered to fully fix this problem. (BZ#586015)

* Due to a wrong test checking for a destination file system, the
Nautilus file manager failed to delete a symbolic link to a folder
which was residing in another file system. With this update, a special
test has been added. As a result, a symbolic link pointing to another
file system can be trashed or deleted properly. (BZ#621394)

* Prior to this update, when directories without a read permission
were marked for copy, the Nautilus file manager skipped these
unreadable directories without notification. With this update,
Nautilus displays an error message and properly informs the user about
the aforementioned problem. (BZ#772307)

* Previously, gnome-vfs2 used the stat() function calls for every file
on the MultiVersion File System (MVFS), used for example by IBM
Rational ClearCase. This behavior significantly slowed down file
operations. With this update, the unnecessary stat() operations have
been limited. As a result, gnome-vfs2 user interfaces, such as
Nautilus, are more responsive. (BZ#822817)

All gnome-vfs2 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ec652c5"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-January/000341.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?642b4d6a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnome-vfs2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2473");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-vfs2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-vfs2-smb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"gnome-vfs2-2.16.2-10.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnome-vfs2-devel-2.16.2-10.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnome-vfs2-smb-2.16.2-10.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-vfs2 / gnome-vfs2-devel / gnome-vfs2-smb");
}
