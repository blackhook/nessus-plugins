#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117582);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-12173"
  );

  script_name(english:"EulerOS Virtualization 2.5.1 : sssd (EulerOS-SA-2018-1273)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the sssd packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerability :

  - It was found that sssd's sysdb_search_user_by_upn_res()
    function did not sanitize requests when querying its
    local cache and was vulnerable to injection. In a
    centralized login environment, if a password hash was
    locally cached for a given user, an authenticated
    attacker could use this flaw to retrieve
    it.(CVE-2017-12173)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1273
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4136f7c");
  script_set_attribute(attribute:"solution", value:
"Update the affected sssd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.5.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libipa_hbac-1.13.0-40.2.h1",
        "libsss_idmap-1.13.0-40.2.h1",
        "libsss_nss_idmap-1.13.0-40.2.h1",
        "python-sssdconfig-1.13.0-40.2.h1",
        "sssd-1.13.0-40.2.h1",
        "sssd-ad-1.13.0-40.2.h1",
        "sssd-client-1.13.0-40.2.h1",
        "sssd-common-1.13.0-40.2.h1",
        "sssd-common-pac-1.13.0-40.2.h1",
        "sssd-ipa-1.13.0-40.2.h1",
        "sssd-krb5-1.13.0-40.2.h1",
        "sssd-krb5-common-1.13.0-40.2.h1",
        "sssd-ldap-1.13.0-40.2.h1",
        "sssd-proxy-1.13.0-40.2.h1"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}
