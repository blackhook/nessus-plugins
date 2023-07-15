#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-972.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102810);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10978", "CVE-2017-10983", "CVE-2017-10984", "CVE-2017-10985", "CVE-2017-10986", "CVE-2017-10987", "CVE-2017-10988");

  script_name(english:"openSUSE Security Update : freeradius-server (openSUSE-2017-972)");
  script_summary(english:"Check for the openSUSE-2017-972 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for freeradius-server fixes the following issues :

  - update to 3.0.15 (bsc#1049086)

  - Bind the lifetime of program name and python path to the
    module

  - CVE-2017-10978: FR-GV-201: Check input / output length
    in make_secret() (bsc#1049086)

  - CVE-2017-10983: FR-GV-206: Fix read overflow when
    decoding DHCP option 63 (bsc#1049086)

  - CVE-2017-10984: FR-GV-301: Fix write overflow in
    data2vp_wimax() (bsc#1049086) 

  - CVE-2017-10985: FR-GV-302: Fix infinite loop and memory
    exhaustion with 'concat' attributes (bsc#1049086)

  - CVE-2017-10986: FR-GV-303: Fix infinite read in
    dhcp_attr2vp() (bsc#1049086)

  - CVE-2017-10987: FR-GV-304: Fix buffer over-read in
    fr_dhcp_decode_suboptions() (bsc#1049086)

  - CVE-2017-10988: FR-GV-305: Decode 'signed' attributes
    correctly. (bsc#1049086) 

  - FR-AD-001: use strncmp() instead of memcmp() for bounded
    data

  - Print messages when we see deprecated configuration
    items

  - Show reasons why we couldn't parse a certificate expiry
    time

  - Be more accepting about truncated ASN1 times.

  - Fix OpenSSL API issue which could leak small amounts of
    memory.

  - For Access-Reject, call rad_authlog() after running the
    post-auth section, just like for Access-Accept.

  - Don't crash when reading corrupted data from session
    resumption cache.

  - Parse port in dhcpclient.

  - Don't leak memory for OpenSSL.

  - Portability fixes taken from OpenBSD port collection.

  - run rad_authlog after post-auth for Access-Reject.

  - Don't process VMPS packets twice.

  - Fix attribute truncation in rlm_perl

  - Fix bug when processing huntgroups.

  - FR-AD-002 - Bind the lifetime of program name and python
    path to the module

  - FR-AD-003 - Pass correct statement length into
    sqlite3_prepare[_v2]

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049086"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeradius-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freeradius-server-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-debuginfo-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-debugsource-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-devel-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-krb5-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-krb5-debuginfo-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-ldap-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-ldap-debuginfo-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-libs-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-libs-debuginfo-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-mysql-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-mysql-debuginfo-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-perl-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-perl-debuginfo-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-postgresql-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-postgresql-debuginfo-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-python-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-python-debuginfo-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-sqlite-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-sqlite-debuginfo-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-utils-3.0.15-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"freeradius-server-utils-debuginfo-3.0.15-3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius-server / freeradius-server-debuginfo / etc");
}
