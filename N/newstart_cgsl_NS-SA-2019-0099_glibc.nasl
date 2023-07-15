#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0099. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127324);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2014-9761",
    "CVE-2015-8776",
    "CVE-2015-8778",
    "CVE-2015-8779",
    "CVE-2017-1000366"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : glibc Multiple Vulnerabilities (NS-SA-2019-0099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has glibc packages installed that are affected by multiple
vulnerabilities:

  - An integer overflow vulnerability was found in hcreate()
    and hcreate_r() functions which could result in an out-
    of-bounds memory access. This could lead to application
    crash or, potentially, arbitrary code execution.
    (CVE-2015-8778)

  - A stack based buffer overflow vulnerability was found in
    the catopen() function. An excessively long string
    passed to the function could cause it to crash or,
    potentially, execute arbitrary code. (CVE-2015-8779)

  - A flaw was found in the way memory was being allocated
    on the stack for user space binaries. If heap (or
    different memory region) and stack memory regions were
    adjacent to each other, an attacker could use this flaw
    to jump over the stack guard gap, cause controlled
    memory corruption on process stack or the adjacent
    memory region, and thus increase their privileges on the
    system. This is glibc-side mitigation which blocks
    processing of LD_LIBRARY_PATH for programs running in
    secure-execution mode and reduces the number of
    allocations performed by the processing of LD_AUDIT,
    LD_PRELOAD, and LD_HWCAP_MASK, making successful
    exploitation of this issue more difficult.
    (CVE-2017-1000366)

  - It was found that out-of-range time values passed to the
    strftime() function could result in an out-of-bounds
    memory access. This could lead to application crash or,
    potentially, information disclosure. (CVE-2015-8776)

  - A stack overflow vulnerability was found in nan*
    functions that could cause applications, which process
    long strings with the nan function, to crash or,
    potentially, execute arbitrary code. (CVE-2014-9761)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0099");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8779");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
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
    "glibc-2.12-1.209.el6_9.2.2",
    "glibc-common-2.12-1.209.el6_9.2.2",
    "glibc-devel-2.12-1.209.el6_9.2.2",
    "glibc-headers-2.12-1.209.el6_9.2.2",
    "glibc-static-2.12-1.209.el6_9.2.2",
    "glibc-utils-2.12-1.192.el6",
    "nscd-2.12-1.209.el6_9.2.2"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
