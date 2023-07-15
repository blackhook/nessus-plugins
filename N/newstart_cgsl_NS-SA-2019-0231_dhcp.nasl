#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0231. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(132472);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/04");

  script_cve_id("CVE-2019-6470");
  script_xref(name:"IAVB", value:"2020-B-0036-S");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : dhcp Vulnerability (NS-SA-2019-0231)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has dhcp packages installed that are affected by a
vulnerability:

  - There had existed in one of the ISC BIND libraries a bug
    in a function that was used by dhcpd when operating in
    DHCPv6 mode. There was also a bug in dhcpd relating to
    the use of this function per its documentation, but the
    bug in the library function prevented this from causing
    any harm. All releases of dhcpd from ISC contain copies
    of this, and other, BIND libraries in combinations that
    have been tested prior to release and are known to not
    present issues like this. Some third-party packagers of
    ISC software have modified the dhcpd source, BIND
    source, or version matchup in ways that create the crash
    potential. Based on reports available to ISC, the crash
    probability is large and no analysis has been done on
    how, or even if, the probability can be manipulated by
    an attacker. Affects: Builds of dhcpd versions prior to
    version 4.4.1 when using BIND versions 9.11.2 or later,
    or BIND versions with specific bug fixes backported to
    them. ISC does not have access to comprehensive version
    lists for all repackagings of dhcpd that are vulnerable.
    In particular, builds from other vendors may also be
    affected. Operators are advised to consult their vendor
    documentation. (CVE-2019-6470)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0231");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL dhcp packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "dhclient-4.2.5-77.el7.centos",
    "dhcp-4.2.5-77.el7.centos",
    "dhcp-common-4.2.5-77.el7.centos",
    "dhcp-debuginfo-4.2.5-77.el7.centos",
    "dhcp-devel-4.2.5-77.el7.centos",
    "dhcp-libs-4.2.5-77.el7.centos"
  ],
  "CGSL MAIN 5.05": [
    "dhclient-4.2.5-77.el7.centos",
    "dhcp-4.2.5-77.el7.centos",
    "dhcp-common-4.2.5-77.el7.centos",
    "dhcp-debuginfo-4.2.5-77.el7.centos",
    "dhcp-devel-4.2.5-77.el7.centos",
    "dhcp-libs-4.2.5-77.el7.centos"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
