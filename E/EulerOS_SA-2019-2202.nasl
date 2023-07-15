#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130664);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-2304",
    "CVE-2015-8915",
    "CVE-2015-8933",
    "CVE-2016-10209",
    "CVE-2016-10349",
    "CVE-2016-10350",
    "CVE-2016-8687",
    "CVE-2016-8688",
    "CVE-2016-8689",
    "CVE-2017-14166",
    "CVE-2017-14501",
    "CVE-2017-14503"
  );
  script_bugtraq_id(
    73137
  );

  script_name(english:"EulerOS 2.0 SP5 : libarchive (EulerOS-SA-2019-2202)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libarchive package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The read_Header function in
    archive_read_support_format_7zip.c in libarchive 3.2.1
    allows remote attackers to cause a denial of service
    (out-of-bounds read) via multiple EmptyStream
    attributes in a header in a 7zip
    archive.(CVE-2016-8689)

  - Stack-based buffer overflow in the safe_fprintf
    function in tar/util.c in libarchive 3.2.1 allows
    remote attackers to cause a denial of service via a
    crafted non-printable multibyte character in a
    filename.(CVE-2016-8687)

  - libarchive 3.3.2 suffers from an out-of-bounds read
    within lha_read_data_none() in
    archive_read_support_format_lha.c when extracting a
    specially crafted lha archive, related to
    lha_crc16.(CVE-2017-14503)

  - An out-of-bounds read flaw exists in parse_file_info in
    archive_read_support_format_iso9660.c in libarchive
    3.3.2 when extracting a specially crafted iso9660 iso
    file, related to
    archive_read_format_iso9660_read_header.(CVE-2017-14501
    )

  - libarchive 3.3.2 allows remote attackers to cause a
    denial of service (xml_data heap-based buffer over-read
    and application crash) via a crafted xar archive,
    related to the mishandling of empty strings in the
    atol8 function in
    archive_read_support_format_xar.c.(CVE-2017-14166)

  - The mtree bidder in libarchive 3.2.1 does not keep
    track of line sizes when extending the read-ahead,
    which allows remote attackers to cause a denial of
    service (crash) via a crafted file, which triggers an
    invalid read in the (1) detect_form or (2) bid_entry
    function in
    libarchive/archive_read_support_format_mtree.c.(CVE-201
    6-8688)

  - The archive_read_format_cab_read_header function in
    archive_read_support_format_cab.c in libarchive 3.2.2
    allows remote attackers to cause a denial of service
    (heap-based buffer over-read and application crash) via
    a crafted file.(CVE-2016-10350)

  - The archive_le32dec function in archive_endian.h in
    libarchive 3.2.2 allows remote attackers to cause a
    denial of service (heap-based buffer over-read and
    application crash) via a crafted file.(CVE-2016-10349)

  - The archive_wstring_append_from_mbs function in
    archive_string.c in libarchive 3.2.2 allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a crafted
    archive file.(CVE-2016-10209)

  - Integer overflow in the archive_read_format_tar_skip
    function in archive_read_support_format_tar.c in
    libarchive before 3.2.0 allows remote attackers to
    cause a denial of service (crash) via a crafted tar
    file.(CVE-2015-8933)

  - bsdcpio in libarchive before 3.2.0 allows remote
    attackers to cause a denial of service (invalid read
    and crash) via crafted cpio file.(CVE-2015-8915)

  - Absolute path traversal vulnerability in bsdcpio in
    libarchive 3.1.2 and earlier allows remote attackers to
    write to arbitrary files via a full pathname in an
    archive.(CVE-2015-2304)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2202
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0be7fa17");
  script_set_attribute(attribute:"solution", value:
"Update the affected libarchive packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libarchive");
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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libarchive-3.1.2-10.h7.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libarchive");
}
