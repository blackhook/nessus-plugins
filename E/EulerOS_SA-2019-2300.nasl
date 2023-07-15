#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131366);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-11091"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");

  script_name(english:"EulerOS 2.0 SP8 : qemu (EulerOS-SA-2019-2300)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the qemu packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - Microarchitectural Store Buffer Data Sampling (MSBDS):
    Store buffers on some microprocessors utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access. A list of impacted products
    can be found here:
    https://www.intel.com/content/dam/www/public/us/en/docu
    ments/corporate-information/SA00233-microcode-update-gu
    idance_05132019.pdf(CVE-2018-12126)

  - Microarchitectural Load Port Data Sampling (MLPDS):
    Load ports on some microprocessors utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access. A list of impacted products
    can be found here:
    https://www.intel.com/content/dam/www/public/us/en/docu
    ments/corporate-information/SA00233-microcode-update-gu
    idance_05132019.pdf(CVE-2018-12127)

  - Microarchitectural Fill Buffer Data Sampling (MFBDS):
    Fill buffers on some microprocessors utilizing
    speculative execution may allow an authenticated user
    to potentially enable information disclosure via a side
    channel with local access. A list of impacted products
    can be found here:
    https://www.intel.com/content/dam/www/public/us/en/docu
    ments/corporate-information/SA00233-microcode-update-gu
    idance_05132019.pdf(CVE-2018-12130)

  - Microarchitectural Data Sampling Uncacheable Memory
    (MDSUM): Uncacheable memory on some microprocessors
    utilizing speculative execution may allow an
    authenticated user to potentially enable information
    disclosure via a side channel with local access. A list
    of impacted products can be found here:
    https://www.intel.com/content/dam/www/public/us/en/docu
    ments/corporate-information/SA00233-microcode-update-gu
    idance_05132019.pdf(CVE-2019-11091)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2300
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c527722b");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-audio-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-audio-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-system-aarch64-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:qemu-ui-sdl");
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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["qemu-audio-alsa-3.0.1-3.h3.eulerosv2r8",
        "qemu-audio-oss-3.0.1-3.h3.eulerosv2r8",
        "qemu-audio-pa-3.0.1-3.h3.eulerosv2r8",
        "qemu-audio-sdl-3.0.1-3.h3.eulerosv2r8",
        "qemu-block-curl-3.0.1-3.h3.eulerosv2r8",
        "qemu-block-dmg-3.0.1-3.h3.eulerosv2r8",
        "qemu-block-gluster-3.0.1-3.h3.eulerosv2r8",
        "qemu-block-iscsi-3.0.1-3.h3.eulerosv2r8",
        "qemu-block-nfs-3.0.1-3.h3.eulerosv2r8",
        "qemu-block-rbd-3.0.1-3.h3.eulerosv2r8",
        "qemu-block-ssh-3.0.1-3.h3.eulerosv2r8",
        "qemu-common-3.0.1-3.h3.eulerosv2r8",
        "qemu-img-3.0.1-3.h3.eulerosv2r8",
        "qemu-kvm-3.0.1-3.h3.eulerosv2r8",
        "qemu-system-aarch64-3.0.1-3.h3.eulerosv2r8",
        "qemu-system-aarch64-core-3.0.1-3.h3.eulerosv2r8",
        "qemu-ui-curses-3.0.1-3.h3.eulerosv2r8",
        "qemu-ui-gtk-3.0.1-3.h3.eulerosv2r8",
        "qemu-ui-sdl-3.0.1-3.h3.eulerosv2r8"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
