#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125002);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2013-1944",
    "CVE-2014-0015",
    "CVE-2014-0138",
    "CVE-2014-3613",
    "CVE-2014-8150",
    "CVE-2016-5419",
    "CVE-2016-7141",
    "CVE-2016-8615",
    "CVE-2016-8617",
    "CVE-2016-8618",
    "CVE-2016-8621",
    "CVE-2016-8622",
    "CVE-2016-8623",
    "CVE-2016-8624",
    "CVE-2016-9586",
    "CVE-2017-1000257",
    "CVE-2017-8817",
    "CVE-2018-1000120",
    "CVE-2018-1000121",
    "CVE-2018-1000122"
  );
  script_bugtraq_id(
    59058,
    65270,
    66457,
    69748,
    71964
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : curl (EulerOS-SA-2019-1549)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the curl packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A NULL pointer dereference flaw was found in the way
    libcurl checks values returned by the openldap
    ldap_get_attribute_ber() function. A malicious LDAP
    server could use this flaw to crash a libcurl client
    application via a specially crafted LDAP
    reply.(CVE-2018-1000121)

  - It was found that libcurl did not safely parse FTP URLs
    when using the CURLOPT_FTP_FILEMETHOD method. An
    attacker, able to provide a specially crafted FTP URL
    to an application using libcurl, could write a NULL
    byte at an arbitrary location, resulting in a crash, or
    an unspecified behavior.(CVE-2018-1000120)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-8623)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-8622)

  - It was found that the libcurl library did not prevent
    TLS session resumption when the client certificate had
    changed. An attacker could potentially use this flaw to
    hijack the authentication of the connection by
    leveraging a previously created connection with a
    different client certificate.(CVE-2016-5419)

  - A buffer overrun flaw was found in the IMAP handler of
    libcurl. By tricking an unsuspecting user into
    connecting to a malicious IMAP server, an attacker
    could exploit this flaw to potentially cause
    information disclosure or crash the
    application.(CVE-2017-1000257)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-8624)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-8621)

  - A buffer over-read exists in curl 7.20.0 to and
    including curl 7.58.0 in the RTSP+RTP handling code
    that allows an attacker to cause a denial of service or
    information leakage(CVE-2018-1000122)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-9586)

  - The FTP wildcard function in curl and libcurl before
    7.57.0 allows remote attackers to cause a denial of
    service (out-of-bounds read and application crash) or
    possibly have unspecified other impact via a string
    that ends with an '' character.(CVE-2017-8817)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-8618)

  - It was found that the libcurl library using the NSS
    (Network Security Services) library as TLS/SSL backend
    incorrectly re-used client certificates for subsequent
    TLS connections in certain cases. An attacker could
    potentially use this flaw to hijack the authentication
    of the connection by leveraging a previously created
    connection with a different client
    certificate.(CVE-2016-7141)

  - cURL and libcurl 7.10.6 through 7.34.0, when more than
    one authentication method is enabled, re-uses NTLM
    connections, which might allow context-dependent
    attackers to authenticate as other users via a
    request.(CVE-2014-0015)

  - The tailMatch function in cookie.c in cURL and libcurl
    before 7.30.0 does not properly match the path domain
    when sending cookies, which allows remote attackers to
    steal cookies via a matching suffix in the domain of a
    URL.(CVE-2013-1944)

  - It was discovered that the libcurl library failed to
    properly handle URLs with embedded end-of-line
    characters. An attacker able to make an application
    using libcurl access a specially crafted URL via an
    HTTP proxy could use this flaw to inject additional
    headers to the request or construct additional
    requests.(CVE-2014-8150)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-8615)

  - The default configuration in cURL and libcurl 7.10.6
    before 7.36.0 re-uses (1) SCP, (2) SFTP, (3) POP3, (4)
    POP3S, (5) IMAP, (6) IMAPS, (7) SMTP, (8) SMTPS, (9)
    LDAP, and (10) LDAPS connections, which might allow
    context-dependent attackers to connect as other users
    via a request, a similar issue to
    CVE-2014-0015.(CVE-2014-0138)

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2016-8617)

  - It was found that the libcurl library did not correctly
    handle partial literal IP addresses when parsing
    received HTTP cookies. An attacker able to trick a user
    into connecting to a malicious server could use this
    flaw to set the user's cookie to a crafted domain,
    making other cookie-related issues easier to
    exploit.(CVE-2014-3613)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1549
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a10efe7");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

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
