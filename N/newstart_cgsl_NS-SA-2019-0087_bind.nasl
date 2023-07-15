#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0087. The text
# itself is copyright (C) ZTE, Inc.


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127303);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-5743");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : bind Vulnerability (NS-SA-2019-0087)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has bind packages installed that are affected by a
vulnerability:

  - A flaw was found in the way bind implemented tunable
    which limited simultaneous TCP client connections. A
    remote attacker could use this flaw to exhaust the pool
    of file descriptors available to named, potentially
    affecting network connections and the management of
    files such as log files or zone journal files. In cases
    where the named process is not limited by OS-enforced
    per-process limits, this could additionally potentially
    lead to exhaustion of all available free file
    descriptors on that system. (CVE-2018-5743)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0087");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

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
    "bind-9.9.4-74.el7_6.1",
    "bind-chroot-9.9.4-74.el7_6.1",
    "bind-debuginfo-9.9.4-74.el7_6.1",
    "bind-devel-9.9.4-74.el7_6.1",
    "bind-libs-9.9.4-74.el7_6.1",
    "bind-libs-lite-9.9.4-74.el7_6.1",
    "bind-license-9.9.4-74.el7_6.1",
    "bind-lite-devel-9.9.4-74.el7_6.1",
    "bind-pkcs11-9.9.4-74.el7_6.1",
    "bind-pkcs11-devel-9.9.4-74.el7_6.1",
    "bind-pkcs11-libs-9.9.4-74.el7_6.1",
    "bind-pkcs11-utils-9.9.4-74.el7_6.1",
    "bind-sdb-9.9.4-74.el7_6.1",
    "bind-sdb-chroot-9.9.4-74.el7_6.1",
    "bind-utils-9.9.4-74.el7_6.1"
  ],
  "CGSL MAIN 5.05": [
    "bind-9.9.4-74.el7_6.1",
    "bind-chroot-9.9.4-74.el7_6.1",
    "bind-debuginfo-9.9.4-74.el7_6.1",
    "bind-devel-9.9.4-74.el7_6.1",
    "bind-libs-9.9.4-74.el7_6.1",
    "bind-libs-lite-9.9.4-74.el7_6.1",
    "bind-license-9.9.4-74.el7_6.1",
    "bind-lite-devel-9.9.4-74.el7_6.1",
    "bind-pkcs11-9.9.4-74.el7_6.1",
    "bind-pkcs11-devel-9.9.4-74.el7_6.1",
    "bind-pkcs11-libs-9.9.4-74.el7_6.1",
    "bind-pkcs11-utils-9.9.4-74.el7_6.1",
    "bind-sdb-9.9.4-74.el7_6.1",
    "bind-sdb-chroot-9.9.4-74.el7_6.1",
    "bind-utils-9.9.4-74.el7_6.1"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
