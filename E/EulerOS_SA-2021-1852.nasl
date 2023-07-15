#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149133);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/04");

  script_cve_id(
    "CVE-2019-12523",
    "CVE-2019-12526",
    "CVE-2019-18676",
    "CVE-2019-18677",
    "CVE-2019-18679",
    "CVE-2020-14058",
    "CVE-2020-25097"
  );

  script_name(english:"EulerOS 2.0 SP3 : squid (EulerOS-SA-2021-1852)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the squid packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in Squid 2.x, 3.x, and 4.x
    through 4.8. Due to incorrect data management, it is
    vulnerable to information disclosure when processing
    HTTP Digest Authentication. Nonce tokens contain the
    raw byte value of a pointer that sits within heap
    memory allocation. This information reduces ASLR
    protections and may aid attackers isolating memory
    areas to target for remote code execution
    attacks.(CVE-2019-18679)

  - An issue was discovered in Squid 3.x and 4.x through
    4.8 when the append_domain setting is used (because the
    appended characters do not properly interact with
    hostname length restrictions). Due to incorrect message
    processing, it can inappropriately redirect traffic to
    origins it should not be delivered to.(CVE-2019-18677)

  - An issue was discovered in Squid 3.x and 4.x through
    4.8. Due to incorrect input validation, there is a
    heap-based buffer overflow that can result in Denial of
    Service to all clients using the proxy. Severity is
    high due to this vulnerability occurring before normal
    security checks any remote client that can reach the
    proxy port can trivially perform the attack via a
    crafted URI scheme.(CVE-2019-18676)

  - An issue was discovered in Squid before 4.12 and 5.x
    before 5.0.3. Due to use of a potentially dangerous
    function, Squid and the default certificate validation
    helper are vulnerable to a Denial of Service when
    opening a TLS connection to an attacker-controlled
    server for HTTPS. This occurs because unrecognized
    error values are mapped to NULL, but later code expects
    that each error value is mapped to a valid error
    string.(CVE-2020-14058)

  - An issue was discovered in Squid before 4.9. URN
    response handling in Squid suffers from a heap-based
    buffer overflow. When receiving data from a remote
    server in response to an URN request, Squid fails to
    ensure that the response can fit within the buffer.
    This leads to attacker controlled data overflowing in
    the heap.(CVE-2019-12526)

  - An issue was discovered in Squid before 4.9. When
    handling a URN request, a corresponding HTTP request is
    made. This HTTP request doesn't go through the access
    checks that incoming HTTP requests go through. This
    causes all access checks to be bypassed and allows
    access to restricted HTTP servers, e.g., an attacker
    can connect to HTTP servers that only listen on
    localhost.(CVE-2019-12523)

  - An issue was discovered in Squid through 4.13 and 5.x
    through 5.0.4. Due to improper input validation, it
    allows a trusted client to perform HTTP Request
    Smuggling and access services otherwise forbidden by
    the security controls. This occurs for certain
    uri_whitespace configuration settings.(CVE-2020-25097)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1852
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc7c3ce1");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["squid-3.5.20-2.2.h13",
        "squid-migration-script-3.5.20-2.2.h13"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
