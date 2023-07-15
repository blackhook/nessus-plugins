#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123890);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2012-6703",
    "CVE-2013-3076",
    "CVE-2013-3231",
    "CVE-2013-3237",
    "CVE-2018-13406",
    "CVE-2018-18386"
  );
  script_bugtraq_id(
    59390,
    59392,
    59398
  );

  script_name(english:"EulerOS Virtualization 2.5.4 : kernel (EulerOS-SA-2019-1204)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A security flaw was found in the Linux kernel in
    drivers/tty/n_tty.c which allows local attackers (ones
    who are able to access pseudo terminals) to lock them
    up and block further usage of any pseudo terminal
    devices due to an EXTPROC versus ICANON confusion in
    TIOCINQ handler.i1/4^CVE-2018-18386i1/4%0

  - The Linux kernel was found vulnerable to an integer
    overflow in the
    drivers/video/fbdev/uvesafb.c:uvesafb_setcmap()
    function. The vulnerability could result in local
    attackers being able to crash the kernel or potentially
    elevate privileges.i1/4^CVE-2018-13406i1/4%0

  - The vsock_stream_sendmsg function in
    net/vmw_vsock/af_vsock.c in the Linux kernel before
    3.9-rc7 does not initialize a certain length variable,
    which allows local users to obtain sensitive
    information from kernel stack memory via a crafted
    recvmsg or recvfrom system call.i1/4^CVE-2013-3237i1/4%0

  - The llc_ui_recvmsg function in net/llc/af_llc.c in the
    Linux kernel before 3.9-rc7 does not initialize a
    certain length variable, which allows local users to
    obtain sensitive information from kernel stack memory
    via a crafted recvmsg or recvfrom system
    call.i1/4^CVE-2013-3231i1/4%0

  - The crypto API in the Linux kernel through 3.9-rc8 does
    not initialize certain length variables, which allows
    local users to obtain sensitive information from kernel
    stack memory via a crafted recvmsg or recvfrom system
    call, related to the hash_recvmsg function in
    crypto/algif_hash.c and the skcipher_recvmsg function
    in crypto/algif_skcipher.c.i1/4^CVE-2013-3076i1/4%0

  - Integer overflow in the snd_compr_allocate_buffer
    function in sound/core/compress_offload.c in the ALSA
    subsystem in the Linux kernel before
    3.6-rc6-next-20120917 allows local users to cause a
    denial of service (insufficient memory allocation) or
    possibly have unspecified other impact via a crafted
    SNDRV_COMPRESS_SET_PARAMS ioctl
    call.i1/4^CVE-2012-6703i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1204
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca40d290");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.4");
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
if (uvp != "2.5.4") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.4");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.1_41",
        "kernel-devel-3.10.0-862.14.1.1_41",
        "kernel-headers-3.10.0-862.14.1.1_41",
        "kernel-tools-3.10.0-862.14.1.1_41",
        "kernel-tools-libs-3.10.0-862.14.1.1_41",
        "kernel-tools-libs-devel-3.10.0-862.14.1.1_41"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
