#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177149);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/13");

  script_cve_id("CVE-2021-3521");

  script_name(english:"EulerOS Virtualization 3.0.6.0 : rpm (EulerOS-SA-2023-2230)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the rpm packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - There is a flaw in RPM's signature functionality. OpenPGP subkeys are associated with a primary key via a
    'binding signature.' RPM does not check the binding signature of subkeys prior to importing them. If an
    attacker is able to add or socially engineer another party to add a malicious subkey to a legitimate
    public key, RPM could wrongly trust a malicious signature. The greatest impact of this flaw is to data
    integrity. To exploit this flaw, an attacker must either compromise an RPM repository or convince an
    administrator to install an untrusted RPM or public key. It is strongly recommended to only use RPMs and
    public keys from trusted sources. (CVE-2021-3521)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2230
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed8146bf");
  script_set_attribute(attribute:"solution", value:
"Update the affected rpm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3521");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-build-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-plugin-ima");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-plugin-prioreset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-plugin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-plugin-syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-plugin-systemd-inhibit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-sign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-sign-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "python2-rpm-4.14.2-1.h19.eulerosv2r8",
  "python3-rpm-4.14.2-1.h19.eulerosv2r8",
  "rpm-4.14.2-1.h19.eulerosv2r8",
  "rpm-apidocs-4.14.2-1.h19.eulerosv2r8",
  "rpm-build-4.14.2-1.h19.eulerosv2r8",
  "rpm-build-libs-4.14.2-1.h19.eulerosv2r8",
  "rpm-cron-4.14.2-1.h19.eulerosv2r8",
  "rpm-devel-4.14.2-1.h19.eulerosv2r8",
  "rpm-libs-4.14.2-1.h19.eulerosv2r8",
  "rpm-plugin-ima-4.14.2-1.h19.eulerosv2r8",
  "rpm-plugin-prioreset-4.14.2-1.h19.eulerosv2r8",
  "rpm-plugin-selinux-4.14.2-1.h19.eulerosv2r8",
  "rpm-plugin-syslog-4.14.2-1.h19.eulerosv2r8",
  "rpm-plugin-systemd-inhibit-4.14.2-1.h19.eulerosv2r8",
  "rpm-sign-4.14.2-1.h19.eulerosv2r8",
  "rpm-sign-libs-4.14.2-1.h19.eulerosv2r8"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rpm");
}
