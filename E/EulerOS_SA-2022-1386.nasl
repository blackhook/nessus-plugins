#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159874);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-3521");

  script_name(english:"EulerOS Virtualization 2.10.1 : rpm (EulerOS-SA-2022-1386)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the rpm packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - There is a flaw in RPM's signature functionality. OpenPGP subkeys are associated with a primary key via a
    binding signature. RPM does not check the binding signature of subkeys prior to importing them. If an
    attacker is able to add or socially engineer another party to add a malicious subkey to a legitimate
    public key, RPM could wrongly trust a malicious signature. The greatest impact of this flaw is to data
    integrity. To exploit this flaw, an attacker must either compromise an RPM repository or convince an
    administrator to install an untrusted RPM or public key. It is strongly recommended to only use RPMs and
    public keys from trusted sources. (CVE-2021-3521)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1386
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e81f35c");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rpm-plugin-systemd-inhibit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.10.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.10.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.10.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "python3-rpm-4.15.1-17.h36.eulerosv2r10",
  "rpm-4.15.1-17.h36.eulerosv2r10",
  "rpm-build-4.15.1-17.h36.eulerosv2r10",
  "rpm-devel-4.15.1-17.h36.eulerosv2r10",
  "rpm-help-4.15.1-17.h36.eulerosv2r10",
  "rpm-libs-4.15.1-17.h36.eulerosv2r10",
  "rpm-plugin-systemd-inhibit-4.15.1-17.h36.eulerosv2r10"
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
