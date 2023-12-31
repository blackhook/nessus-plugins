#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-5520.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75788);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-3368", "CVE-2011-3607", "CVE-2011-4317");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-SU-2012:0212-1)");
  script_summary(english:"Check for the apache2-5520 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several security issues in the Apache2 webserver.

CVE-2011-3368, CVE-2011-4317: This update also includes several fixes
for a mod_proxy reverse exposure via RewriteRule or ProxyPassMatch
directives.

CVE-2011-3607: Integer overflow in ap_pregsub function resulting in a
heap based buffer overflow could potentially allow local attackers to
gain privileges

In addition to that the following changes were made :

  - new template file:
    /etc/apache2/vhosts.d/vhost-ssl.template allow TLSv1
    only, browser match stuff commented out.

  - rc script /etc/init.d/apache2: handle reload with
    deleted binaries by message to stdout only, but refrain
    from sending signals."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=722545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-02/msg00014.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/05");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"apache2-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-debuginfo-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-debugsource-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-devel-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-example-certificates-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-example-pages-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-itk-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-itk-debuginfo-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-prefork-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-prefork-debuginfo-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-utils-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-utils-debuginfo-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-worker-2.2.17-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-worker-debuginfo-2.2.17-4.11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-devel / apache2-example-certificates / etc");
}
