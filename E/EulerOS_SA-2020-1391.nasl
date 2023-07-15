#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135520);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-10195",
    "CVE-2019-14867"
  );

  script_name(english:"EulerOS 2.0 SP3 : ipa (EulerOS-SA-2020-1391)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ipa packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in IPA, all 4.6.x versions before
    4.6.7, all 4.7.x versions before 4.7.4 and all 4.8.x
    versions before 4.8.3, in the way that FreeIPA's batch
    processing API logged operations. This included passing
    user passwords in clear text on FreeIPA masters. Batch
    processing of commands with passwords as arguments or
    options is not performed by default in FreeIPA but is
    possible by third-party components. An attacker having
    access to system logs on FreeIPA masters could use this
    flaw to produce log file content with passwords
    exposed.(CVE-2019-10195)

  - A flaw was found in IPA, all 4.6.x versions before
    4.6.7, all 4.7.x versions before 4.7.4 and all 4.8.x
    versions before 4.8.3, in the way the internal function
    ber_scanf() was used in some components of the IPA
    server, which parsed kerberos key data. An
    unauthenticated attacker who could trigger parsing of
    the krb principal key could cause the IPA server to
    crash or in some conditions, cause arbitrary code to be
    executed on the server hosting the IPA
    server.(CVE-2019-14867)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1391
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eecb4bfc");
  script_set_attribute(attribute:"solution", value:
"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["ipa-admintools-4.4.0-14.4.h5",
        "ipa-client-4.4.0-14.4.h5",
        "ipa-client-common-4.4.0-14.4.h5",
        "ipa-common-4.4.0-14.4.h5",
        "ipa-server-4.4.0-14.4.h5",
        "ipa-server-common-4.4.0-14.4.h5",
        "ipa-server-dns-4.4.0-14.4.h5",
        "ipa-server-trust-ad-4.4.0-14.4.h5",
        "python2-ipaclient-4.4.0-14.4.h5",
        "python2-ipalib-4.4.0-14.4.h5",
        "python2-ipaserver-4.4.0-14.4.h5"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa");
}
