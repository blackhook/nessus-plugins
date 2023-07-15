#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1346.
#

include("compat.inc");

if (description)
{
  script_id(130599);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2019-6470");
  script_xref(name:"ALAS", value:"2019-1346");
  script_xref(name:"IAVB", value:"2020-B-0036-S");

  script_name(english:"Amazon Linux 2 : dhcp (ALAS-2019-1346)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"There had existed in one of the ISC BIND libraries a bug in a function
that was used by dhcpd when operating in DHCPv6 mode. There was also a
bug in dhcpd relating to the use of this function per its
documentation, but the bug in the library function prevented this from
causing any harm. All releases of dhcpd from ISC contain copies of
this, and other, BIND libraries in combinations that have been tested
prior to release and are known to not present issues like this. Some
third-party packagers of ISC software have modified the dhcpd source,
BIND source, or version matchup in ways that create the crash
potential. Based on reports available to ISC, the crash probability is
large and no analysis has been done on how, or even if, the
probability can be manipulated by an attacker. Affects: Builds of
dhcpd versions prior to version 4.4.1 when using BIND versions 9.11.2
or later, or BIND versions with specific bug fixes backported to them.
ISC does not have access to comprehensive version lists for all
repackagings of dhcpd that are vulnerable. In particular, builds from
other vendors may also be affected. Operators are advised to consult
their vendor documentation.(CVE-2019-6470)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1346.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update dhcp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"dhclient-4.2.5-77.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"dhcp-4.2.5-77.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"dhcp-common-4.2.5-77.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"dhcp-debuginfo-4.2.5-77.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"dhcp-devel-4.2.5-77.amzn2.1.1")) flag++;
if (rpm_check(release:"AL2", reference:"dhcp-libs-4.2.5-77.amzn2.1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-common / dhcp-debuginfo / dhcp-devel / etc");
}
