#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124891);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2015-7575",
    "CVE-2018-10844",
    "CVE-2018-10845"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : gnutls (EulerOS-SA-2019-1388)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gnutls packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - It was found that the GnuTLS implementation of
    HMAC-SHA-384 was vulnerable to a Lucky thirteen style
    attack. Remote attackers could use this flaw to conduct
    distinguishing attacks and plain text recovery attacks
    via statistical analysis of timing data using crafted
    packets.(CVE-2018-10845)

  - It was found that the GnuTLS implementation of
    HMAC-SHA-256 was vulnerable to a Lucky thirteen style
    attack. Remote attackers could use this flaw to conduct
    distinguishing attacks and plaintext-recovery attacks
    via statistical analysis of timing data using crafted
    packets.(CVE-2018-10844)

  - A flaw was found in the way TLS 1.2 could use the MD5
    hash function for signing ServerKeyExchange and Client
    Authentication packets during a TLS handshake. A
    man-in-the-middle attacker able to force a TLS
    connection to use the MD5 hash function could use this
    flaw to conduct collision attacks to impersonate a TLS
    server or an authenticated TLS client.(CVE-2015-7575)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1388
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?017f51f8");
  script_set_attribute(attribute:"solution", value:
"Update the affected gnutls packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10845");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-dane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gnutls-utils");
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

pkgs = ["gnutls-3.3.26-9.h3",
        "gnutls-c++-3.3.26-9.h3",
        "gnutls-dane-3.3.26-9.h3",
        "gnutls-devel-3.3.26-9.h3",
        "gnutls-utils-3.3.26-9.h3"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls");
}
