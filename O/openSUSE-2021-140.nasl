#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-140.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145314);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-26217", "CVE-2020-26258", "CVE-2020-26259");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE Security Update : xstream (openSUSE-2021-140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for xstream fixes the following issues :

xstream was updated to version 1.4.15.

  - CVE-2020-26217: Fixed a remote code execution due to
    insecure XML deserialization when relying on blocklists
    (bsc#1180994).

  - CVE-2020-26258: Fixed a server-side request forgery
    vulnerability (bsc#1180146).

  - CVE-2020-26259: Fixed an arbitrary file deletion
    vulnerability (bsc#1180145).

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180994");
  script_set_attribute(attribute:"solution", value:
"Update the affected xstream packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream-benchmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xstream-parent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"xstream-1.4.15-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xstream-benchmark-1.4.15-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xstream-javadoc-1.4.15-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"xstream-parent-1.4.15-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xstream / xstream-benchmark / xstream-javadoc / xstream-parent");
}
