#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130846);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id(
    "CVE-2019-6470"
  );
  script_xref(name:"IAVB", value:"2020-B-0036-S");

  script_name(english:"EulerOS 2.0 SP5 : dhcp (EulerOS-SA-2019-2137)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the dhcp packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerability :

  - The Dynamic Host Configuration Protocol (DHCP) is a
    protocol that allows individual devices on an IP
    network to get their own network configuration
    information, including an IP address, a subnet mask,
    and a broadcast address. The dhcp packages provide a
    relay agent and ISC DHCP service required to enable and
    administer DHCP on a network.Security Fix(es):There had
    existed in one of the ISC BIND libraries a bug in a
    function that was used by dhcpd when operating in
    DHCPv6 mode. There was also a bug in dhcpd relating to
    the use of this function per its documentation, but the
    bug in the library function prevented this from causing
    any harm. All releases of dhcpd from ISC contain copies
    of this, and other, BIND libraries in combinations that
    have been tested prior to release and are known to not
    present issues like this. Some third-party packagers of
    ISC software have modified the dhcpd source, BIND
    source, or version matchup in ways that create the
    crash potential. Based on reports available to ISC, the
    crash probability is large and no analysis has been
    done on how, or even if, the probability can be
    manipulated by an attacker. Affects: Builds of dhcpd
    versions prior to version 4.4.1 when using BIND
    versions 9.11.2 or later, or BIND versions with
    specific bug fixes backported to them. ISC does not
    have access to comprehensive version lists for all
    repackagings of dhcpd that are vulnerable. In
    particular, builds from other vendors may also be
    affected. Operators are advised to consult their vendor
    documentation.(CVE-2019-6470)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2137
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97b749cb");
  script_set_attribute(attribute:"solution", value:
"Update the affected dhcp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["dhclient-4.2.5-68.1.h12.eulerosv2r7",
        "dhcp-4.2.5-68.1.h12.eulerosv2r7",
        "dhcp-common-4.2.5-68.1.h12.eulerosv2r7",
        "dhcp-libs-4.2.5-68.1.h12.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp");
}
