#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129452);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-12525",
    "CVE-2019-12527",
    "CVE-2019-12529",
    "CVE-2019-12854",
    "CVE-2019-13345"
  );

  script_name(english:"EulerOS 2.0 SP8 : squid (EulerOS-SA-2019-2093)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the squid package installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in Squid 3.3.9 through 3.5.28
    and 4.x through 4.7. When Squid is configured to use
    Digest authentication, it parses the header
    Proxy-Authorization. It searches for certain tokens
    such as domain, uri, and qop. Squid checks if this
    token's value starts with a quote and ends with one. If
    so, it performs a memcpy of its length minus 2. Squid
    never checks whether the value is just a single quote
    (which would satisfy its requirements), leading to a
    memcpy of its length minus 1.(CVE-2019-12525)

  - The cachemgr.cgi web module of Squid through 4.7 has
    XSS via the user_name or auth
    parameter.(CVE-2019-13345)

  - An issue was discovered in Squid 4.0.23 through 4.7.
    When checking Basic Authentication with
    HttpHeader::getAuth, Squid uses a global buffer to
    store the decoded data. Squid does not check that the
    decoded length isn't greater than the buffer, leading
    to a heap-based buffer overflow with user controlled
    data.(CVE-2019-12527)

  - An issue was discovered in Squid 2.x through
    2.7.STABLE9, 3.x through 3.5.28, and 4.x through 4.7.
    When Squid is configured to use Basic Authentication,
    the Proxy-Authorization header is parsed via uudecode.
    uudecode determines how many bytes will be decoded by
    iterating over the input and checking its table. The
    length is then used to start decoding the string. There
    are no checks to ensure that the length it calculates
    isn't greater than the input buffer. This leads to
    adjacent memory being decoded as well. An attacker
    would not be able to retrieve the decoded data unless
    the Squid maintainer had configured the display of
    usernames on error pages.(CVE-2019-12529)

  - Due to incorrect string termination, Squid cachemgr.cgi
    4.0 through 4.7 may access unallocated memory. On
    systems with memory access protections, this can cause
    the CGI process to terminate unexpectedly, resulting in
    a denial of service for all clients using
    it.(CVE-2019-12854)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2093
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f540e5a");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["squid-4.2-2.h1.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
