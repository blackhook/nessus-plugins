#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0125. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(127373);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");

  script_name(english:"NewStart CGSL MAIN 4.05 : kernel Vulnerability (NS-SA-2019-0125)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has kernel packages installed that are affected by a
vulnerability:

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions (a commonly used performance
    optimization). There are three primary variants of the
    issue which differ in the way the speculative execution
    can be exploited. Variant CVE-2017-5715 triggers the
    speculative execution by utilizing branch target
    injection. It relies on the presence of a precisely-
    defined instruction sequence in the privileged code as
    well as the fact that memory accesses may cause
    allocation into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to cross the syscall and guest/host
    boundaries and read privileged memory by conducting
    targeted cache side-channel attacks. (CVE-2017-5715)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0125");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5715");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "kernel-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-abi-whitelists-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-debug-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-debug-debuginfo-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-debug-devel-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-debuginfo-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-debuginfo-common-x86_64-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-devel-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-doc-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-firmware-2.6.32-642.13.1.el6.cgsl7680",
    "kernel-headers-2.6.32-642.13.1.el6.cgsl7680",
    "perf-2.6.32-642.13.1.el6.cgsl7680",
    "perf-debuginfo-2.6.32-642.13.1.el6.cgsl7680",
    "python-perf-2.6.32-642.13.1.el6.cgsl7680",
    "python-perf-debuginfo-2.6.32-642.13.1.el6.cgsl7680"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
