#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171166);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-39282",
    "CVE-2022-39283",
    "CVE-2022-39316",
    "CVE-2022-39317",
    "CVE-2022-39318",
    "CVE-2022-39347",
    "CVE-2022-41877"
  );

  script_name(english:"EulerOS 2.0 SP8 : freerdp (EulerOS-SA-2023-1313)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the freerdp packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - FreeRDP is a free remote desktop protocol library and clients. FreeRDP based clients on unix systems using
    `/parallel` command line switch might read uninitialized data and send it to the server the client is
    currently connected to. FreeRDP based server implementations are not affected. Please upgrade to 2.8.1
    where this issue is patched. If unable to upgrade, do not use parallel port redirection (`/parallel`
    command line switch) as a workaround. (CVE-2022-39282)

  - FreeRDP is a free remote desktop protocol library and clients. All FreeRDP based clients when using the
    `/video` command line switch might read uninitialized data, decode it as audio/video and display the
    result. FreeRDP based server implementations are not affected. This issue has been patched in version
    2.8.1. If you cannot upgrade do not use the `/video` switch. (CVE-2022-39283)

  - FreeRDP is a free remote desktop protocol library and clients. In affected versions there is an out of
    bound read in ZGFX decoder component of FreeRDP. A malicious server can trick a FreeRDP based client to
    read out of bound data and try to decode it likely resulting in a crash. This issue has been addressed in
    the 2.9.0 release. Users are advised to upgrade. (CVE-2022-39316)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing a
    range check for input offset index in ZGFX decoder. A malicious server can trick a FreeRDP based client to
    read out of bound data and try to decode it. This issue has been addressed in version 2.9.0. There are no
    known workarounds for this issue. (CVE-2022-39317)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input validation in `urbdrc` channel. A malicious server can trick a FreeRDP based client to crash with
    division by zero. This issue has been addressed in version 2.9.0. All users are advised to upgrade. Users
    unable to upgrade should not use the `/usb` redirection switch. (CVE-2022-39318)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    path canonicalization and base path check for `drive` channel. A malicious server can trick a FreeRDP
    based client to read files outside the shared directory. This issue has been addressed in version 2.9.0
    and all users are advised to upgrade. Users unable to upgrade should not use the `/drive`, `/drives` or
    `+home-drive` redirection switch. (CVE-2022-39347)

  - FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing
    input length validation in `drive` channel. A malicious server can trick a FreeRDP based client to read
    out of bound data and send it back to the server. This issue has been addressed in version 2.9.0 and all
    users are advised to upgrade. Users unable to upgrade should not use the drive redirection channel -
    command line options `/drive`, `+drives` or `+home-drive`. (CVE-2022-41877)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1313
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d6505b7");
  script_set_attribute(attribute:"solution", value:
"Update the affected freerdp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39283");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwinpr");
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
  "freerdp-2.0.0-44.rc3.h15.eulerosv2r8",
  "freerdp-libs-2.0.0-44.rc3.h15.eulerosv2r8",
  "libwinpr-2.0.0-44.rc3.h15.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp");
}
