#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update krb5-2443.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46730);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-1321");

  script_name(english:"openSUSE Security Update : krb5 (openSUSE-SU-2010:0292-1)");
  script_summary(english:"Check for the krb5-2443 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a denial-of-service vulnerability in kadmind. A
remote attack can send a malformed GSS-API token that triggers a NULL
pointer dereference. (CVE-2010-1321: CVSS v2 Base Score: 6.8 (MEDIUM)
(AV:N/AC:L/Au:S/C:N/I:N/A:C))"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=596826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2010-05/msg00027.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-apps-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-apps-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE11.2", reference:"krb5-1.7-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"krb5-apps-clients-1.7-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"krb5-apps-servers-1.7-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"krb5-client-1.7-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"krb5-devel-1.7-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"krb5-plugin-kdb-ldap-1.7-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"krb5-plugin-preauth-pkinit-1.7-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"krb5-server-1.7-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"krb5-32bit-1.7-6.6.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"krb5-devel-32bit-1.7-6.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
