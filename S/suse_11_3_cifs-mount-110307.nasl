#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update cifs-mount-4110.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75447);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-0719");

  script_name(english:"openSUSE Security Update : cifs-mount (openSUSE-SU-2011:0403-1)");
  script_summary(english:"Check for the cifs-mount-4110 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"With this update samba is not prone to a remote denial of service
attack anymore. (CVE-2011-0719)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=670431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2011-04/msg00076.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cifs-mount packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"ldapsmb-1.34b-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libldb-devel-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libldb0-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libnetapi-devel-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libnetapi0-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsmbclient-devel-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsmbclient0-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsmbsharemodes-devel-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libsmbsharemodes0-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtalloc-devel-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtalloc2-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtdb-devel-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtdb1-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtevent-devel-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libtevent0-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libwbclient-devel-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"libwbclient0-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-client-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-devel-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-krb-printing-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"samba-winbind-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libsmbclient0-32bit-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libtdb1-32bit-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"libwbclient0-32bit-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"samba-32bit-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"samba-client-32bit-3.5.4-5.9.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"samba-winbind-32bit-3.5.4-5.9.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
