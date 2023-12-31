#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60653);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-6552");

  script_name(english:"Scientific Linux Security Update : gfs2-utils on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple insecure temporary file use flaws were discovered in GFS2
user level utilities. A local attacker could use these flaws to
overwrite an arbitrary file writable by a victim running those
utilities (typically root) with the output of the utilities via a
symbolic link attack. (CVE-2008-6552)

This update also fixes the following bugs :

  - gfs2_fsck now properly detects and repairs problems with
    sequence numbers on GFS2 file systems.

  - GFS2 user utilities now use the file system UUID.

  - gfs2_grow now properly updates the file system size
    during operation.

  - gfs2_fsck now returns the proper exit codes.

  - gfs2_convert now properly frees blocks when removing
    free blocks up to height 2.

  - the gfs2_fsck manual page has been renamed to fsck.gfs2
    to match current standards.

  - the 'gfs2_tool df' command now provides human-readable
    output.

  - mounting GFS2 file systems with the noatime or noquota
    option now works properly.

  - new capabilities have been added to the gfs2_edit tool
    to help in testing and debugging GFS and GFS2 issues.

  - the 'gfs2_tool df' command no longer segfaults on file
    systems with a block size other than 4k.

  - the gfs2_grow manual page no longer references the '-r'
    option, which has been removed.

  - the 'gfs2_tool unfreeze' command no longer hangs during
    use.

  - gfs2_convert no longer corrupts file systems when
    converting from GFS to GFS2.

  - gfs2_fsck no longer segfaults when encountering a block
    which is listed as both a data and stuffed directory
    inode.

  - gfs2_fsck can now fix file systems even if the journal
    is already locked for use.

  - a GFS2 file system's metadata is now properly copied
    with 'gfs2_edit savemeta' and 'gfs2_edit restoremeta'.

  - the gfs2_edit savemeta function now properly saves
    blocks of type 2.

  - 'gfs2_convert -vy' now works properly on the PowerPC
    architecture.

  - when mounting a GFS2 file system as '/', mount_gfs2 no
    longer fails after being unable to find the file system
    in '/proc/mounts'.

  - gfs2_fsck no longer segfaults when fixing 'EA leaf block
    type' problems."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0910&L=scientific-linux-errata&T=0&P=561
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee5e8852"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gfs2-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"gfs2-utils-0.1.62-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
