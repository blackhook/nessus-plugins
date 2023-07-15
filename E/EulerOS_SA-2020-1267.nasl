#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134733);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id(
    "CVE-2019-6470"
  );
  script_xref(name:"IAVB", value:"2020-B-0036-S");

  script_name(english:"EulerOS Virtualization 3.0.2.2 : dhcp-noddns (EulerOS-SA-2020-1267)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the dhcp-noddns packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerability :

  - There had existed in one of the ISC BIND libraries a
    bug in a function that was used by dhcpd when operating
    in DHCPv6 mode. There was also a bug in dhcpd relating
    to the use of this function per its documentation, but
    the bug in the library function prevented this from
    causing any harm. All releases of dhcpd from ISC
    contain copies of this, and other, BIND libraries in
    combinations that have been tested prior to release and
    are known to not present issues like this. Some
    third-party packagers of ISC software have modified the
    dhcpd source, BIND source, or version matchup in ways
    that create the crash potential. Based on reports
    available to ISC, the crash probability is large and no
    analysis has been done on how, or even if, the
    probability can be manipulated by an attacker. Affects:
    Builds of dhcpd versions prior to version 4.4.1 when
    using BIND versions 9.11.2 or later, or BIND versions
    with specific bug fixes backported to them. ISC does
    not have access to comprehensive version lists for all
    repackagings of dhcpd that are vulnerable. In
    particular, builds from other vendors may also be
    affected. Operators are advised to consult their vendor
    documentation.(CVE-2019-6470)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1267
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a1843f7");
  script_set_attribute(attribute:"solution", value:
"Update the affected dhcp-noddns package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhclient-noddns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-noddns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-noddns-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-noddns-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["dhclient-noddns-4.2.5-68.1.h12",
        "dhcp-noddns-4.2.5-68.1.h12",
        "dhcp-noddns-common-4.2.5-68.1.h12",
        "dhcp-noddns-libs-4.2.5-68.1.h12"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp-noddns");
}
