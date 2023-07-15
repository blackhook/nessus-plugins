#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124794);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2013-0211",
    "CVE-2015-8916",
    "CVE-2015-8917",
    "CVE-2015-8919",
    "CVE-2015-8920",
    "CVE-2015-8921",
    "CVE-2015-8922",
    "CVE-2015-8923",
    "CVE-2015-8924",
    "CVE-2015-8925",
    "CVE-2015-8926",
    "CVE-2015-8928",
    "CVE-2015-8930",
    "CVE-2015-8931",
    "CVE-2015-8932",
    "CVE-2015-8934",
    "CVE-2016-1541",
    "CVE-2016-4300",
    "CVE-2016-4302",
    "CVE-2016-4809",
    "CVE-2016-5418",
    "CVE-2016-5844",
    "CVE-2016-6250",
    "CVE-2016-7166"
  );
  script_bugtraq_id(58926);

  script_name(english:"EulerOS Virtualization 3.0.1.0 : libarchive (EulerOS-SA-2019-1470)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libarchive package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A vulnerability was found in libarchive. A specially
    crafted MTREE file could cause a small out-of-bounds
    read, potentially disclosing a small amount of
    application memory.(CVE-2015-8925)

  - A vulnerability was found in libarchive. An attempt to
    create an ISO9660 volume with 2GB or 4GB filenames
    could cause the application to crash.(CVE-2016-6250)

  - A vulnerability was found in libarchive. A specially
    crafted RAR file could cause the application to read
    memory beyond the end of the decompression
    buffer.(CVE-2015-8934)

  - A vulnerability was found in libarchive's handling of
    7zip data. A specially crafted 7zip file can cause a
    integer overflow resulting in memory corruption that
    can lead to code execution.(CVE-2016-4300)

  - A vulnerability was found in libarchive. A specially
    crafted 7Z file could trigger a NULL pointer
    dereference, causing the application to
    crash.(CVE-2015-8922)

  - Undefined behavior (signed integer overflow) was
    discovered in libarchive, in the ISO parser. A crafted
    file could potentially cause denial of
    service.(CVE-2016-5844)

  - A vulnerability was found in libarchive. A specially
    crafted AR archive could cause the application to read
    a single byte of application memory, potentially
    disclosing it to the attacker.(CVE-2015-8920)

  - A vulnerability was found in libarchive. A specially
    crafted mtree file could cause libarchive to read
    beyond a statically declared structure, potentially
    disclosing application memory.(CVE-2015-8921)

  - A vulnerability was found in libarchive. A specially
    crafted LZA/LZH file could cause a small out-of-bounds
    read, potentially disclosing a few bytes of application
    memory.(CVE-2015-8919)

  - A vulnerability was found in libarchive. A specially
    crafted ISO file could cause the application to consume
    resources until it hit a memory limit, leading to a
    crash or denial of service.(CVE-2015-8930)

  - A vulnerability was found in libarchive. A specially
    crafted TAR file could trigger an out-of-bounds read,
    potentially causing the application to disclose a small
    amount of application memory.(CVE-2015-8924)

  - A vulnerability was found in libarchive. A specially
    crafted MTREE file could cause a limited out-of-bounds
    read, potentially disclosing contents of application
    memory.(CVE-2015-8928)

  - A vulnerability was found in libarchive. A specially
    crafted CAB file could cause the application
    dereference a NULL pointer, leading to a
    crash.(CVE-2015-8917)

  - A vulnerability was found in libarchive. A specially
    crafted RAR file could cause the application
    dereference a NULL pointer, leading to a
    crash.(CVE-2015-8916)

  - A vulnerability was found in libarchive's handling of
    RAR archives. A specially crafted RAR file can cause a
    heap overflow, potentially leading to code execution in
    the context of the application.(CVE-2016-4302)

  - Undefined behavior (invalid left shift) was discovered
    in libarchive, in how Compress streams are identified.
    This could cause certain files to be mistakenly
    identified as Compress archives and fail to
    read.(CVE-2015-8932)

  - A vulnerability was found in libarchive. A specially
    crafted gzip file can cause libarchive to allocate
    memory without limit, eventually leading to a
    crash.(CVE-2016-7166)

  - Undefined behavior (signed integer overflow) was
    discovered in libarchive, in the MTREE parser's
    calculation of maximum and minimum dates. A crafted
    mtree file could potentially cause denial of
    service.(CVE-2015-8931)

  - A flaw was found in the way libarchive handled hardlink
    archive entries of non-zero size. Combined with flaws
    in libarchive's file system sandboxing, this issue
    could cause an application using libarchive to
    overwrite arbitrary files with arbitrary data from the
    archive.(CVE-2016-5418)

  - Integer signedness error in the archive_write_zip_data
    function in archive_write_set_format_zip.c in
    libarchive 3.1.2 and earlier, when running on 64-bit
    machines, allows context-dependent attackers to cause a
    denial of service (crash) via unspecified vectors,
    which triggers an improper conversion between unsigned
    and signed types, leading to a buffer
    overflow.(CVE-2013-0211)

  - A vulnerability was found in libarchive. A specially
    crafted zip file can provide an incorrect compressed
    size, which may allow an attacker to place arbitrary
    code on the heap and execute it in the context of the
    application.(CVE-2016-1541)

  - A vulnerability was found in libarchive. A specially
    crafted cpio archive containing a symbolic link to a
    ridiculously large target path can cause memory
    allocation to fail, resulting in any attempt to view or
    extract the archive crashing.(CVE-2016-4809)

  - A vulnerability was found in libarchive. A specially
    crafted ZIP file could cause a few bytes of application
    memory in a 256-byte region to be
    disclosed.(CVE-2015-8923)

  - A vulnerability was found in libarchive. A specially
    crafted RAR file could cause the application to
    disclose a 128k block of memory from an uncontrolled
    location.(CVE-2015-8926)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1470
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?381a14a8");
  script_set_attribute(attribute:"solution", value:
"Update the affected libarchive packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6250");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-1541");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ibarchive");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ibarchive-3.1.2-10.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libarchive");
}
