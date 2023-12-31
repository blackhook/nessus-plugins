#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update cifs-mount-2128.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45341);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-0547", "CVE-2010-0926");

  script_name(english:"openSUSE Security Update : cifs-mount (cifs-mount-2128)");
  script_summary(english:"Check for the cifs-mount-2128 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"With enabled 'wide links' samba follows symbolic links on the server
side, therefore allowing clients to overwrite arbitrary files
(CVE-2010-0926). This update changes the default setting to have 'wide
links' disabled by default. The new default only works if 'wide links'
is not set explicitly in smb.conf.

Due to a race condition in mount.cifs a local attacker could corrupt
/etc/mtab if mount.cifs is installed setuid root. mount.cifs is not
setuid root by default and it's not recommended to change that
(CVE-2010-0547)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=577868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=577925"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cifs-mount packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_cwe_id(20, 22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cifs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"cifs-mount-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"ldapsmb-1.34b-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libnetapi-devel-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libnetapi0-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libsmbclient-devel-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libsmbclient0-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libsmbsharemodes-devel-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libsmbsharemodes0-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libtalloc-devel-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libtalloc1-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libtdb-devel-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libtdb1-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libwbclient-devel-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libwbclient0-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"samba-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"samba-client-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"samba-devel-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"samba-krb-printing-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"samba-winbind-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libsmbclient0-32bit-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libtalloc1-32bit-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libtdb1-32bit-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"libwbclient0-32bit-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"samba-32bit-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"samba-client-32bit-3.4.3-3.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"samba-winbind-32bit-3.4.3-3.2.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cifs-mount / ldapsmb / libnetapi-devel / libnetapi0 / etc");
}
