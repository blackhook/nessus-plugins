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
  script_id(82248);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-8105", "CVE-2014-8112");

  script_name(english:"Scientific Linux Security Update : 389-ds-base on SL7.x x86_64 (20150305)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information disclosure flaw was found in the way the 389 Directory
Server stored information in the Changelog that is exposed via the
'cn=changelog' LDAP sub-tree. An unauthenticated user could in certain
cases use this flaw to read data from the Changelog, which could
include sensitive information such as plain-text passwords.
(CVE-2014-8105)

It was found that when the nsslapd-unhashed-pw-switch 389 Directory
Server configuration option was set to 'off', it did not prevent the
writing of unhashed passwords into the Changelog. This could
potentially allow an authenticated user able to access the Changelog
to read sensitive information. (CVE-2014-8112)

Enhancements :

  - Added new WinSync configuration parameters:
    winSyncSubtreePair for synchronizing multiple subtrees,
    as well as winSyncWindowsFilter and
    winSyncDirectoryFilter for synchronizing restricted sets
    by filters.

  - It is now possible to stop, start, or configure plug-ins
    without the need to restart the server for the change to
    take effect.

  - Access control related to the MODDN and MODRDN
    operations has been updated: the source and destination
    targets can be specified in the same access control
    instruction.

  - The nsDS5ReplicaBindDNGroup attribute for using a group
    distinguished name in binding to replicas has been
    added.

  - WinSync now supports range retrieval. If more than the
    MaxValRange number of attribute values exist per
    attribute, WinSync synchronizes all the attributes to
    the directory server using the range retrieval.

  - Support for the RFC 4527 Read Entry Controls and RFC
    4533 Content Synchronization Operation LDAP standards
    has been added.

  - The Referential Integrity (referint) plug-in can now use
    an alternate configuration area. The PlugInArg plug-in
    configuration now uses unique configuration attributes.
    Configuration changes no longer require a server
    restart.

  - The logconv.pl log analysis tool now supports gzip,
    bzip2, and xz compressed files and also TAR archives and
    compressed TAR archives of these files.

  - Only the Directory Manager could add encoded passwords
    or force users to change their password after a reset.
    Users defined in the passwordAdminDN attribute can now
    also do this.

  - The 'nsslapd-memberofScope' configuration parameter has
    been added to the MemberOf plug-in. With MemberOf
    enabled and a scope defined, moving a group out of scope
    with a MODRDN operation failed. Moving a member entry
    out of scope now correctly removes the memberof value.

  - The alwaysRecordLoginAttr attribute has been addded to
    the Account Policy plug-in configuration entry, which
    allows to distinguish between an attribute for checking
    the activity of an account and an attribute to be
    updated at successful login.

  - A root DSE search, using the ldapsearch command with the
    '-s base -b ''' options, returns only the user
    attributes instead of the operational attributes. The
    'nsslapd-return-default' option has been added for
    backward compatibility.

  - The configuration of the MemberOf plug-in can be stored
    in a suffix mapped to a back-end database, which allows
    MemberOf configuration to be replicated.

  - Added support for the SSL versions from the range
    supported by the NSS library available on the system.
    Due to the POODLE vulnerability, SSLv3 is disabled by
    default even if NSS supports it."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=2637
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df52762a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-1.3.3.1-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-debuginfo-1.3.3.1-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.3.1-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.3.1-13.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-debuginfo / 389-ds-base-devel / etc");
}
