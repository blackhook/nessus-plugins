#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0098. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127323);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-8890",
    "CVE-2017-9075",
    "CVE-2017-9076",
    "CVE-2017-9077"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : kernel Multiple Vulnerabilities (NS-SA-2019-0098)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has kernel packages installed that are affected by multiple
vulnerabilities:

  - The inet_csk_clone_lock function in
    net/ipv4/inet_connection_sock.c in the Linux kernel
    allows attackers to cause a denial of service (double
    free) or possibly have unspecified other impact by
    leveraging use of the accept system call. An
    unprivileged local user could use this flaw to induce
    kernel memory corruption on the system, leading to a
    crash. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely. (CVE-2017-8890)

  - The sctp_v6_create_accept_sk function in net/sctp/ipv6.c
    in the Linux kernel mishandles inheritance, which allows
    local users to cause a denial of service or possibly
    have unspecified other impact via crafted system calls,
    a related issue to CVE-2017-8890. An unprivileged local
    user could use this flaw to induce kernel memory
    corruption on the system, leading to a crash. Due to the
    nature of the flaw, privilege escalation cannot be fully
    ruled out, although we believe it is unlikely.
    (CVE-2017-9075)

  - The IPv6 DCCP implementation in the Linux kernel
    mishandles inheritance, which allows local users to
    cause a denial of service or possibly have unspecified
    other impact via crafted system calls, a related issue
    to CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely. (CVE-2017-9076)

  - The tcp_v6_syn_recv_sock function in net/ipv6/tcp_ipv6.c
    in the Linux kernel mishandles inheritance, which allows
    local users to cause a denial of service or possibly
    have unspecified other impact via crafted system calls,
    a related issue to CVE-2017-8890. An unprivileged local
    user could use this flaw to induce kernel memory
    corruption on the system, leading to a crash. Due to the
    nature of the flaw, privilege escalation cannot be fully
    ruled out, although we believe it is unlikely.
    (CVE-2017-9077)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0098");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9077");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/10");
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
    "kernel-2.6.32-642.13.1.el6.cgsl7399",
    "kernel-abi-whitelists-2.6.32-642.13.1.el6.cgsl7259",
    "kernel-debug-2.6.32-642.13.1.el6.cgsl7259",
    "kernel-debug-devel-2.6.32-642.13.1.el6.cgsl7259",
    "kernel-devel-2.6.32-642.13.1.el6.cgsl7399",
    "kernel-doc-2.6.32-642.13.1.el6.cgsl7259",
    "kernel-firmware-2.6.32-642.13.1.el6.cgsl7259",
    "kernel-headers-2.6.32-642.13.1.el6.cgsl7399",
    "perf-2.6.32-642.13.1.el6.cgsl7259"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
