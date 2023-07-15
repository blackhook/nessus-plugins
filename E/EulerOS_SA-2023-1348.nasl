#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171190);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2019-3886");

  script_name(english:"EulerOS 2.0 SP8 : libvirt (EulerOS-SA-2023-1348)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libvirt packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - An incorrect permissions check was discovered in libvirt 4.8.0 and above. The readonly permission was
    allowed to invoke APIs depending on the guest agent which could lead to potentially disclosing unintended
    information or denial of service by causing libvirt to block. (CVE-2019-3886)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1348
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e46e4956");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvirt packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3886");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-iscsi-direct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-daemon-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "libvirt-bash-completion-4.7.0-5.h2.eulerosv2r8",
  "libvirt-client-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-config-network-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-config-nwfilter-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-interface-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-network-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-nodedev-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-nwfilter-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-qemu-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-secret-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-storage-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-storage-core-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-storage-disk-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-storage-iscsi-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-storage-iscsi-direct-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-storage-logical-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-storage-mpath-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-driver-storage-scsi-4.7.0-5.h2.eulerosv2r8",
  "libvirt-daemon-kvm-4.7.0-5.h2.eulerosv2r8",
  "libvirt-libs-4.7.0-5.h2.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt");
}
