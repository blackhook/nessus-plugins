#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1337 and 
# CentOS Errata and Security Advisory 2009:1337 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43786);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-6552");
  script_bugtraq_id(32179);
  script_xref(name:"RHSA", value:"2009:1337");

  script_name(english:"CentOS 5 : gfs2-utils (CESA-2009:1337)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gfs2-utils package that fixes multiple security issues and
various bugs is now available for Red Hat Enterprise Linux 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The gfs2-utils package provides the user-space tools necessary to
mount, create, maintain, and test GFS2 file systems.

Multiple insecure temporary file use flaws were discovered in GFS2
user level utilities. A local attacker could use these flaws to
overwrite an arbitrary file writable by a victim running those
utilities (typically root) with the output of the utilities via a
symbolic link attack. (CVE-2008-6552)

This update also fixes the following bugs :

* gfs2_fsck now properly detects and repairs problems with sequence
numbers on GFS2 file systems.

* GFS2 user utilities now use the file system UUID.

* gfs2_grow now properly updates the file system size during
operation.

* gfs2_fsck now returns the proper exit codes.

* gfs2_convert now properly frees blocks when removing free blocks up
to height 2.

* the gfs2_fsck manual page has been renamed to fsck.gfs2 to match
current standards.

* the 'gfs2_tool df' command now provides human-readable output.

* mounting GFS2 file systems with the noatime or noquota option now
works properly.

* new capabilities have been added to the gfs2_edit tool to help in
testing and debugging GFS and GFS2 issues.

* the 'gfs2_tool df' command no longer segfaults on file systems with
a block size other than 4k.

* the gfs2_grow manual page no longer references the '-r' option,
which has been removed.

* the 'gfs2_tool unfreeze' command no longer hangs during use.

* gfs2_convert no longer corrupts file systems when converting from
GFS to GFS2.

* gfs2_fsck no longer segfaults when encountering a block which is
listed as both a data and stuffed directory inode.

* gfs2_fsck can now fix file systems even if the journal is already
locked for use.

* a GFS2 file system's metadata is now properly copied with 'gfs2_edit
savemeta' and 'gfs2_edit restoremeta'.

* the gfs2_edit savemeta function now properly saves blocks of type 2.

* 'gfs2_convert -vy' now works properly on the PowerPC architecture.

* when mounting a GFS2 file system as '/', mount_gfs2 no longer fails
after being unable to find the file system in '/proc/mounts'.

* gfs2_fsck no longer segfaults when fixing 'EA leaf block type'
problems.

All gfs2-utils users should upgrade to this updated package, which
resolves these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-September/016151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d9349fa"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-September/016152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77d21c89"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gfs2-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gfs2-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"gfs2-utils-0.1.62-1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gfs2-utils");
}
