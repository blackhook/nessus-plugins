#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0196. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(129929);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/30");

  script_cve_id("CVE-2018-15686", "CVE-2018-16866", "CVE-2018-16888");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : systemd Multiple Vulnerabilities (NS-SA-2019-0196)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has systemd packages installed that are affected
by multiple vulnerabilities:

  - A vulnerability in unit_deserialize of systemd allows an
    attacker to supply arbitrary state across systemd re-
    execution via NotifyAccess. This can be used to
    improperly influence systemd execution and possibly lead
    to root privilege escalation. Affected releases are
    systemd versions up to and including 239.
    (CVE-2018-15686)

  - It was discovered systemd does not correctly check the
    content of PIDFile files before using it to kill
    processes. When a service is run from an unprivileged
    user (e.g. User field set in the service file), a local
    attacker who is able to write to the PIDFile of the
    mentioned service may use this flaw to trick systemd
    into killing other services and/or privileged processes.
    Versions before v237 are vulnerable. (CVE-2018-16888)

  - An out of bounds read was discovered in systemd-journald
    in the way it parses log messages that terminate with a
    colon ':'. A local attacker can use this flaw to
    disclose process memory data. Versions from v221 to v239
    are vulnerable. (CVE-2018-16866)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0196");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL systemd packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15686");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
    "libgudev1-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "libgudev1-devel-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "systemd-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "systemd-debuginfo-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "systemd-devel-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "systemd-journal-gateway-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "systemd-libs-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "systemd-networkd-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "systemd-python-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "systemd-resolved-219-67.el7.cgslv5.0.14.g2212dcb.lite",
    "systemd-sysv-219-67.el7.cgslv5.0.14.g2212dcb.lite"
  ],
  "CGSL MAIN 5.04": [
    "libgudev1-219-67.el7.cgslv5.0.10.gf4ec716",
    "libgudev1-devel-219-67.el7.cgslv5.0.10.gf4ec716",
    "systemd-219-67.el7.cgslv5.0.10.gf4ec716",
    "systemd-debuginfo-219-67.el7.cgslv5.0.10.gf4ec716",
    "systemd-devel-219-67.el7.cgslv5.0.10.gf4ec716",
    "systemd-journal-gateway-219-67.el7.cgslv5.0.10.gf4ec716",
    "systemd-libs-219-67.el7.cgslv5.0.10.gf4ec716",
    "systemd-networkd-219-67.el7.cgslv5.0.10.gf4ec716",
    "systemd-python-219-67.el7.cgslv5.0.10.gf4ec716",
    "systemd-resolved-219-67.el7.cgslv5.0.10.gf4ec716",
    "systemd-sysv-219-67.el7.cgslv5.0.10.gf4ec716"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
