#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118418);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id(
    "CVE-2016-9586",
    "CVE-2017-8817",
    "CVE-2017-1000254",
    "CVE-2018-1000120",
    "CVE-2018-1000121",
    "CVE-2018-1000122",
    "CVE-2018-1000301"
  );

  script_name(english:"EulerOS Virtualization 2.5.0 : curl (EulerOS-SA-2018-1330)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the curl package installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

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
    information leakage(CVE-2018-1000122)

  - curl version curl 7.20.0 to and including curl 7.59.0
    contains a Buffer Over-read vulnerability in denial of
    service that can result in curl can be tricked into
    reading data beyond the end of a heap based buffer used
    to store downloaded rtsp content.(CVE-2018-1000301)

  - curl version curl 7.20.0 to and including curl 7.59.0
    contains a Buffer Over-read vulnerability in denial of
    service that can result in curl can be tricked into
    reading data beyond the end of a heap based buffer used
    to store downloaded rtsp content.(CVE-2016-9586)

  - libcurl may read outside of a heap allocated buffer
    when doing FTP. When libcurl connects to an FTP server
    and successfully logs in (anonymous or not), it asks
    the server for the current directory with the `PWD`
    command. The server then responds with a 257 response
    containing the path, inside double quotes. The returned
    path name is then kept by libcurl for subsequent uses.
    Due to a flaw in the string parser for this directory
    name, a directory name passed like this but without a
    closing double quote would lead to libcurl not adding a
    trailing NUL byte to the buffer holding the name. When
    libcurl would then later access the string, it could
    read beyond the allocated heap buffer and crash or
    wrongly access data beyond the buffer, thinking it was
    part of the path. A malicious server could abuse this
    fact and effectively prevent libcurl-based clients to
    work with it - the PWD command is always issued on new
    FTP connections and the mistake has a high chance of
    causing a segfault. The simple fact that this has issue
    remained undiscovered for this long could suggest that
    malformed PWD responses are rare in benign servers. We
    are not aware of any exploit of this flaw. This bug was
    introduced in commit
    [415d2e7cb7](https://github.com/curl/curl/commit/415d2e
    7cb7), March 2005. In libcurl version 7.56.0, the
    parser always zero terminates the string but also
    rejects it if not terminated properly with a final
    double quote.i1/4^CVE-2017-1000254i1/4%0

  - The FTP wildcard function in curl and libcurl before
    7.57.0 allows remote attackers to cause a denial of
    service (out-of-bounds read and application crash) or
    possibly have unspecified other impact via a string
    that ends with an '[' character.The FTP wildcard
    function in curl and libcurl before 7.57.0 allows
    remote attackers to cause a denial of service
    (out-of-bounds read and application crash) or possibly
    have unspecified other impact via a string that ends
    with an '[' character.i1/4^CVE-2017-8817i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1330
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4aa41f3c");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.5.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["curl-7.29.0-35.h7"];

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
