#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124914);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id("CVE-2017-12173", "CVE-2018-10852");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : sssd (EulerOS-SA-2019-1411)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the sssd packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - The UNIX pipe which sudo uses to contact SSSD and read
    the available sudo rules from SSSD utilizes too broad
    of a set of permissions. Any user who can send a
    message using the same raw protocol that sudo and SSSD
    use can read the sudo rules available for any
    user.(CVE-2018-10852)

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
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1411
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62c45445");
  script_set_attribute(attribute:"solution", value:
"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10852");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-12173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libsss_sudo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["libipa_hbac-1.16.0-19.5.h3",
        "libsss_autofs-1.16.0-19.5.h3",
        "libsss_certmap-1.16.0-19.5.h3",
        "libsss_idmap-1.16.0-19.5.h3",
        "libsss_nss_idmap-1.16.0-19.5.h3",
        "libsss_sudo-1.16.0-19.5.h3",
        "python-sssdconfig-1.16.0-19.5.h3",
        "sssd-1.16.0-19.5.h3",
        "sssd-ad-1.16.0-19.5.h3",
        "sssd-client-1.16.0-19.5.h3",
        "sssd-common-1.16.0-19.5.h3",
        "sssd-common-pac-1.16.0-19.5.h3",
        "sssd-ipa-1.16.0-19.5.h3",
        "sssd-krb5-1.16.0-19.5.h3",
        "sssd-krb5-common-1.16.0-19.5.h3",
        "sssd-ldap-1.16.0-19.5.h3",
        "sssd-proxy-1.16.0-19.5.h3"];

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
