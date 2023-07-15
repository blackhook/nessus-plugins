#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-565.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148763);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/21");

  script_cve_id("CVE-2019-15945", "CVE-2019-15946", "CVE-2019-19479", "CVE-2019-19480", "CVE-2019-20792", "CVE-2020-26570", "CVE-2020-26571", "CVE-2020-26572");

  script_name(english:"openSUSE Security Update : opensc (openSUSE-2021-565)");
  script_summary(english:"Check for the openSUSE-2021-565 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for opensc fixes the following issues :

&#9; - CVE-2019-15945: Fixed an out-of-bounds access of an ASN.1
Bitstring in decode_bit_string (bsc#1149746).

  - CVE-2019-15946: Fixed an out-of-bounds access of an
    ASN.1 Octet string in asn1_decode_entry (bsc#1149747)

  - CVE-2019-19479: Fixed an incorrect read operation during
    parsing of a SETCOS file attribute (bsc#1158256)

  - CVE-2019-19480: Fixed an improper free operation in
    sc_pkcs15_decode_prkdf_entry (bsc#1158307).

  - CVE-2019-20792: Fixed a double free in
    coolkey_free_private_data (bsc#1170809). 

  - CVE-2020-26570: Fixed a buffer overflow in
    sc_oberthur_read_file (bsc#1177364).

  - CVE-2020-26571: Fixed a stack-based buffer overflow in
    gemsafe GPK smart card software driver (bsc#1177380)

  - CVE-2020-26572: Fixed a stack-based buffer overflow in
    tcos_decipher (bsc#1177378).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1170809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177380"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected opensc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opensc-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"opensc-0.19.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"opensc-debuginfo-0.19.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"opensc-debugsource-0.19.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"opensc-32bit-0.19.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"opensc-32bit-debuginfo-0.19.0-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opensc / opensc-debuginfo / opensc-debugsource / opensc-32bit / etc");
}
