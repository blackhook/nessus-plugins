#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132274);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2016-6170",
    "CVE-2018-5741",
    "CVE-2018-5745",
    "CVE-2019-6465"
  );

  script_name(english:"EulerOS 2.0 SP3 : bind (EulerOS-SA-2019-2557)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the bind packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - 'managed-keys' is a feature which allows a BIND
    resolver to automatically maintain the keys used by
    trust anchors which operators configure for use in
    DNSSEC validation. Due to an error in the managed-keys
    feature it is possible for a BIND server which uses
    managed-keys to exit due to an assertion failure if,
    during key rollover, a trust anchor's keys are replaced
    with keys which use an unsupported algorithm. Versions
    affected: BIND 9.9.0 -> 9.10.8-P1, 9.11.0 -> 9.11.5-P1,
    9.12.0 -> 9.12.3-P1, and versions 9.9.3-S1 -> 9.11.5-S3
    of BIND 9 Supported Preview Edition. Versions 9.13.0 ->
    9.13.6 of the 9.13 development branch are also
    affected. Versions prior to BIND 9.9.0 have not been
    evaluated for vulnerability to
    CVE-2018-5745.(CVE-2018-5745)

  - Controls for zone transfers may not be properly applied
    to Dynamically Loadable Zones (DLZs) if the zones are
    writable Versions affected: BIND 9.9.0 -> 9.10.8-P1,
    9.11.0 -> 9.11.5-P2, 9.12.0 -> 9.12.3-P2, and versions
    9.9.3-S1 -> 9.11.5-S3 of BIND 9 Supported Preview
    Edition. Versions 9.13.0 -> 9.13.6 of the 9.13
    development branch are also affected. Versions prior to
    BIND 9.9.0 have not been evaluated for vulnerability to
    CVE-2019-6465.(CVE-2019-6465)

  - ISC BIND through 9.9.9-P1, 9.10.x through 9.10.4-P1,
    and 9.11.x through 9.11.0b1 allows primary DNS servers
    to cause a denial of service (secondary DNS server
    crash) via a large AXFR response, and possibly allows
    IXFR servers to cause a denial of service (IXFR client
    crash) via a large IXFR response and allows remote
    authenticated users to cause a denial of service
    (primary DNS server crash) via a large UPDATE
    message.(CVE-2016-6170)

  - To provide fine-grained controls over the ability to
    use Dynamic DNS (DDNS) to update records in a zone,
    BIND 9 provides a feature called update-policy. Various
    rules can be configured to limit the types of updates
    that can be performed by a client, depending on the key
    used when sending the update request. Unfortunately,
    some rule types were not initially documented, and when
    documentation for them was added to the Administrator
    Reference Manual (ARM) in change #3112, the language
    that was added to the ARM at that time incorrectly
    described the behavior of two rule types,
    krb5-subdomain and ms-subdomain. This incorrect
    documentation could mislead operators into believing
    that policies they had configured were more restrictive
    than they actually were. This affects BIND versions
    prior to BIND 9.11.5 and BIND 9.12.3.(CVE-2018-5741)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2557
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5aa36a50");
  script_set_attribute(attribute:"solution", value:
"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6465");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-5741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["bind-9.9.4-61.1.h6",
        "bind-chroot-9.9.4-61.1.h6",
        "bind-libs-9.9.4-61.1.h6",
        "bind-libs-lite-9.9.4-61.1.h6",
        "bind-license-9.9.4-61.1.h6",
        "bind-pkcs11-9.9.4-61.1.h6",
        "bind-pkcs11-libs-9.9.4-61.1.h6",
        "bind-pkcs11-utils-9.9.4-61.1.h6",
        "bind-utils-9.9.4-61.1.h6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
