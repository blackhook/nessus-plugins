#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0024. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127183);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2014-9402",
    "CVE-2015-5180",
    "CVE-2016-3706",
    "CVE-2017-12132",
    "CVE-2017-15670",
    "CVE-2017-15804",
    "CVE-2018-1000001"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : glibc Multiple Vulnerabilities (NS-SA-2019-0024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has glibc packages installed that are affected by
multiple vulnerabilities:

  - The GNU C Library (aka glibc or libc6) before 2.27
    contains an off-by-one error leading to a heap-based
    buffer overflow in the glob function in glob.c, related
    to the processing of home directories using the ~
    operator followed by a long string. (CVE-2017-15670)

  - The DNS stub resolver in the GNU C Library (aka glibc or
    libc6) before version 2.26, when EDNS support is
    enabled, will solicit large UDP responses from name
    servers, potentially simplifying off-path DNS spoofing
    attacks due to IP fragmentation. (CVE-2017-12132)

  - The glob function in glob.c in the GNU C Library (aka
    glibc or libc6) before 2.27 contains a buffer overflow
    during unescaping of user names with the ~ operator.
    (CVE-2017-15804)

  - res_query in libresolv in glibc before 2.25 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and process crash). (CVE-2015-5180)

  - The nss_dns implementation of getnetbyname in GNU C
    Library (aka glibc) before 2.21, when the DNS backend in
    the Name Service Switch configuration is enabled, allows
    remote attackers to cause a denial of service (infinite
    loop) by sending a positive answer while a network name
    is being process. (CVE-2014-9402)

  - In glibc 2.26 and earlier there is confusion in the
    usage of getcwd() by realpath() which can be used to
    write before the destination buffer leading to a buffer
    underflow and potential code execution.
    (CVE-2018-1000001)

  - Stack-based buffer overflow in the getaddrinfo function
    in sysdeps/posix/getaddrinfo.c in the GNU C Library (aka
    glibc or libc6) allows remote attackers to cause a
    denial of service (crash) via vectors involving hostent
    conversion. NOTE: this vulnerability exists because of
    an incomplete fix for CVE-2013-4458. (CVE-2016-3706)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0024");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15804");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc realpath() Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/24");
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
    "glibc-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-common-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-debuginfo-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-debuginfo-common-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-devel-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-headers-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-i18n-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-iconv-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-lang-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-locale-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-static-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-tools-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "glibc-utils-2.17-222.el7.cgslv5lite.0.6.g0d82438",
    "nscd-2.17-222.el7.cgslv5lite.0.6.g0d82438"
  ],
  "CGSL MAIN 5.04": [
    "glibc-2.17-222.el7.cgslv5.0.1.gd23aea5",
    "glibc-common-2.17-222.el7.cgslv5.0.1.gd23aea5",
    "glibc-debuginfo-2.17-222.el7.cgslv5.0.1.gd23aea5",
    "glibc-debuginfo-common-2.17-222.el7.cgslv5.0.1.gd23aea5",
    "glibc-devel-2.17-222.el7.cgslv5.0.1.gd23aea5",
    "glibc-headers-2.17-222.el7.cgslv5.0.1.gd23aea5",
    "glibc-static-2.17-222.el7.cgslv5.0.1.gd23aea5",
    "glibc-utils-2.17-222.el7.cgslv5.0.1.gd23aea5",
    "nscd-2.17-222.el7.cgslv5.0.1.gd23aea5"
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
