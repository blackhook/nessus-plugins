#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132220);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-5974",
    "CVE-2017-5975",
    "CVE-2017-5976",
    "CVE-2017-5977",
    "CVE-2017-5978",
    "CVE-2017-5979",
    "CVE-2017-5981",
    "CVE-2018-16548",
    "CVE-2018-6381",
    "CVE-2018-6484",
    "CVE-2018-6540",
    "CVE-2018-6541",
    "CVE-2018-6869"
  );

  script_name(english:"EulerOS 2.0 SP3 : zziplib (EulerOS-SA-2019-2685)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the zziplib package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in ZZIPlib through 0.13.69.
    There is a memory leak triggered in the function
    __zzip_parse_root_directory in zip.c, which will lead
    to a denial of service attack.(CVE-2018-16548)

  - Heap-based buffer overflow in the __zzip_get32 function
    in fetch.c in zziplib 0.13.62 allows remote attackers
    to cause a denial of service (crash) via a crafted ZIP
    file.(CVE-2017-5974)

  - Heap-based buffer overflow in the __zzip_get64 function
    in fetch.c in zziplib 0.13.62 allows remote attackers
    to cause a denial of service (crash) via a crafted ZIP
    file.(CVE-2017-5975)

  - Heap-based buffer overflow in the
    zzip_mem_entry_extra_block function in memdisk.c in
    zziplib 0.13.62 allows remote attackers to cause a
    denial of service (crash) via a crafted ZIP
    file.(CVE-2017-5976)

  - In ZZIPlib 0.13.67, there is a bus error caused by
    loading of a misaligned address (when handling
    disk64_trailer local entries) in
    __zzip_fetch_disk_trailer (zzip/zip.c). Remote
    attackers could leverage this vulnerability to cause a
    denial of service via a crafted zip
    file.(CVE-2018-6541)

  - In ZZIPlib 0.13.67, there is a bus error caused by
    loading of a misaligned address in the
    zzip_disk_findfirst function of zzip/mmapped.c. Remote
    attackers could leverage this vulnerability to cause a
    denial of service via a crafted zip
    file.(CVE-2018-6540)

  - In ZZIPlib 0.13.67, there is a memory alignment error
    and bus error in the __zzip_fetch_disk_trailer function
    of zzip/zip.c. Remote attackers could leverage this
    vulnerability to cause a denial of service via a
    crafted zip file.(CVE-2018-6484)

  - In ZZIPlib 0.13.67, there is a segmentation fault
    caused by invalid memory access in the zzip_disk_fread
    function (zzip/mmapped.c) because the size variable is
    not validated against the amount of file->stored
    data.(CVE-2018-6381)

  - In ZZIPlib 0.13.68, there is an uncontrolled memory
    allocation and a crash in the
    __zzip_parse_root_directory function of zzip/zip.c.
    Remote attackers could leverage this vulnerability to
    cause a denial of service via a crafted zip
    file.(CVE-2018-6869)

  - seeko.c in zziplib 0.13.62 allows remote attackers to
    cause a denial of service (assertion failure and crash)
    via a crafted ZIP file.(CVE-2017-5981)

  - The prescan_entry function in fseeko.c in zziplib
    0.13.62 allows remote attackers to cause a denial of
    service (NULL pointer dereference and crash) via a
    crafted ZIP file.(CVE-2017-5979)

  - The zzip_mem_entry_extra_block function in memdisk.c in
    zziplib 0.13.62 allows remote attackers to cause a
    denial of service (invalid memory read and crash) via a
    crafted ZIP file.(CVE-2017-5977)

  - The zzip_mem_entry_new function in memdisk.c in zziplib
    0.13.62 allows remote attackers to cause a denial of
    service (out-of-bounds read and crash) via a crafted
    ZIP file.(CVE-2017-5978)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2685
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48c509bf");
  script_set_attribute(attribute:"solution", value:
"Update the affected zziplib packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6869");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:zziplib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["zziplib-0.13.62-9.h3"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zziplib");
}
