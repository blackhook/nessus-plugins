#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124993);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-1000257",
    "CVE-2018-1000007",
    "CVE-2018-1000120",
    "CVE-2018-1000121",
    "CVE-2018-1000122",
    "CVE-2018-1000301",
    "CVE-2018-14618"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : curl (EulerOS-SA-2019-1540)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the curl packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - curl before version 7.61.1 is vulnerable to a buffer
    overrun in the NTLM authentication code. The internal
    function Curl_ntlm_core_mk_nt_hash multiplies the
    length of the password by two (SUM) to figure out how
    large temporary storage area to allocate from the heap.
    The length value is then subsequently used to iterate
    over the password and generate output into the
    allocated storage buffer. On systems with a 32 bit
    size_t, the math to calculate SUM triggers an integer
    overflow when the password length exceeds 2GB (2^31
    bytes). This integer overflow usually causes a very
    small buffer to actually get allocated instead of the
    intended very huge one, making the use of that buffer
    end up in a heap buffer overflow. (This bug is almost
    identical to CVE-2017-8816.)(CVE-2018-14618)

  - It was found that libcurl did not safely parse FTP URLs
    when using the CURLOPT_FTP_FILEMETHOD method. An
    attacker, able to provide a specially crafted FTP URL
    to an application using libcurl, could write a NULL
    byte at an arbitrary location, resulting in a crash, or
    an unspecified behavior.(CVE-2018-1000120)

  - A NULL pointer dereference flaw was found in the way
    libcurl checks values returned by the openldap
    ldap_get_attribute_ber() function. A malicious LDAP
    server could use this flaw to crash a libcurl client
    application via a specially crafted LDAP
    reply.(CVE-2018-1000121)

  - A buffer over-read exists in curl 7.20.0 to and
    including curl 7.58.0 in the RTSP+RTP handling code
    that allows an attacker to cause a denial of service or
    information leakage.(CVE-2018-1000122)

  - curl version curl 7.20.0 to and including curl 7.59.0
    contains a CWE-126: Buffer Over-read vulnerability in
    denial of service that can result in curl can be
    tricked into reading data beyond the end of a heap
    based buffer used to store downloaded RTSP content..
    (CVE-2018-1000301)

  - A buffer overrun flaw was found in the IMAP handler of
    libcurl. By tricking an unsuspecting user into
    connecting to a malicious IMAP server, an attacker
    could exploit this flaw to potentially cause
    information disclosure or crash the
    application.(CVE-2017-1000257)

  - It was found that curl and libcurl might send their
    Authentication header to a third party HTTP server upon
    receiving an HTTP REDIRECT reply. This could leak
    authentication token to external entities.
    (CVE-2018-1000007)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1540
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ed5b0f5");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcurl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["curl-7.29.0-46.h10",
        "libcurl-7.29.0-46.h10"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl");
}
