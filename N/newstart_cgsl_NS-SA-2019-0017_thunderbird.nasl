#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0017. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127172);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-5125",
    "CVE-2018-5127",
    "CVE-2018-5129",
    "CVE-2018-5144",
    "CVE-2018-5145",
    "CVE-2018-5146"
  );

  script_name(english:"NewStart CGSL MAIN 5.04 : thunderbird Multiple Vulnerabilities (NS-SA-2019-0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has thunderbird packages installed that are affected by
multiple vulnerabilities:

  - Memory safety bugs were reported in Firefox 58 and
    Firefox ESR 52.6. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort
    that some of these could be exploited to run arbitrary
    code. This vulnerability affects Thunderbird < 52.7,
    Firefox ESR < 52.7, and Firefox < 59. (CVE-2018-5125)

  - A buffer overflow can occur when manipulating the SVG
    animatedPathSegList through script. This results in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 52.7, Firefox ESR < 52.7, and
    Firefox < 59. (CVE-2018-5127)

  - A lack of parameter validation on IPC messages results
    in a potential out-of-bounds write through malformed IPC
    messages. This can potentially allow for sandbox escape
    through memory corruption in the parent process. This
    vulnerability affects Thunderbird < 52.7, Firefox ESR <
    52.7, and Firefox < 59. (CVE-2018-5129)

  - An integer overflow can occur during conversion of text
    to some Unicode character sets due to an unchecked
    length parameter. This vulnerability affects Firefox ESR
    < 52.7 and Thunderbird < 52.7. (CVE-2018-5144)

  - Memory safety bugs were reported in Firefox ESR 52.6.
    These bugs showed evidence of memory corruption and we
    presume that with enough effort that some of these could
    be exploited to run arbitrary code. This vulnerability
    affects Firefox ESR < 52.7 and Thunderbird < 52.7.
    (CVE-2018-5145)

  - An out of bounds write flaw was found in the processing
    of vorbis audio data. A maliciously crafted file or
    audio stream could cause the application to crash or,
    potentially, execute arbitrary code. (CVE-2018-5146)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0017");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5145");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
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

if (release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 5.04": [
    "thunderbird-52.7.0-1.el7.centos",
    "thunderbird-debuginfo-52.7.0-1.el7.centos"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
