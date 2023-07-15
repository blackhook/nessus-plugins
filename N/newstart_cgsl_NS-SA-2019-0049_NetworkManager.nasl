#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0049. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127232);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id("CVE-2018-15688");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : NetworkManager Vulnerability (NS-SA-2019-0049)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has NetworkManager packages installed that are
affected by a vulnerability:

  - It was discovered that systemd-network does not
    correctly keep track of a buffer size when constructing
    DHCPv6 packets. This flaw may lead to an integer
    underflow that can be used to produce an heap-based
    buffer overflow. A malicious host on the same network
    segment as the victim's one may advertise itself as a
    DHCPv6 server and exploit this flaw to cause a Denial of
    Service or potentially gain code execution on the
    victim's machine. (CVE-2018-15688)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0049");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL NetworkManager packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15688");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "NetworkManager-1.12.0-8.el7_6",
    "NetworkManager-adsl-1.12.0-8.el7_6",
    "NetworkManager-bluetooth-1.12.0-8.el7_6",
    "NetworkManager-config-server-1.12.0-8.el7_6",
    "NetworkManager-debuginfo-1.12.0-8.el7_6",
    "NetworkManager-dispatcher-routing-rules-1.12.0-8.el7_6",
    "NetworkManager-glib-1.12.0-8.el7_6",
    "NetworkManager-glib-devel-1.12.0-8.el7_6",
    "NetworkManager-libnm-1.12.0-8.el7_6",
    "NetworkManager-libnm-devel-1.12.0-8.el7_6",
    "NetworkManager-ovs-1.12.0-8.el7_6",
    "NetworkManager-ppp-1.12.0-8.el7_6",
    "NetworkManager-team-1.12.0-8.el7_6",
    "NetworkManager-tui-1.12.0-8.el7_6",
    "NetworkManager-wifi-1.12.0-8.el7_6",
    "NetworkManager-wwan-1.12.0-8.el7_6"
  ],
  "CGSL MAIN 5.04": [
    "NetworkManager-1.12.0-8.el7_6",
    "NetworkManager-adsl-1.12.0-8.el7_6",
    "NetworkManager-bluetooth-1.12.0-8.el7_6",
    "NetworkManager-config-server-1.12.0-8.el7_6",
    "NetworkManager-debuginfo-1.12.0-8.el7_6",
    "NetworkManager-dispatcher-routing-rules-1.12.0-8.el7_6",
    "NetworkManager-glib-1.12.0-8.el7_6",
    "NetworkManager-glib-devel-1.12.0-8.el7_6",
    "NetworkManager-libnm-1.12.0-8.el7_6",
    "NetworkManager-libnm-devel-1.12.0-8.el7_6",
    "NetworkManager-ovs-1.12.0-8.el7_6",
    "NetworkManager-ppp-1.12.0-8.el7_6",
    "NetworkManager-team-1.12.0-8.el7_6",
    "NetworkManager-tui-1.12.0-8.el7_6",
    "NetworkManager-wifi-1.12.0-8.el7_6",
    "NetworkManager-wwan-1.12.0-8.el7_6"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager");
}
