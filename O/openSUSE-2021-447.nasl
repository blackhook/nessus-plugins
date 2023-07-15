#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-447.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(147927);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/24");

  script_cve_id("CVE-2020-13936");

  script_name(english:"openSUSE Security Update : velocity (openSUSE-2021-447)");
  script_summary(english:"Check for the openSUSE-2021-447 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for velocity fixes the following issues :

  - CVE-2020-13936: Fixed an arbitrary code execution when
    attacker is able to modify templates (bsc#1183360).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183360"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected velocity packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:velocity-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:velocity-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:velocity-manual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

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

if ( rpm_check(release:"SUSE15.2", reference:"velocity-1.7-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"velocity-demo-1.7-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"velocity-javadoc-1.7-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"velocity-manual-1.7-lp152.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "velocity / velocity-demo / velocity-javadoc / velocity-manual");
}
