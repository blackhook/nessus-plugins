#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139998);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2018-19396",
    "CVE-2018-19518",
    "CVE-2019-11048",
    "CVE-2020-7059",
    "CVE-2020-7060",
    "CVE-2020-7062",
    "CVE-2020-7063",
    "CVE-2020-7067"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : php (EulerOS-SA-2020-1895)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - In PHP versions 7.2.x below 7.2.30, 7.3.x below 7.3.17
    and 7.4.x below 7.4.5, if PHP is compiled with EBCDIC
    support (uncommon), urldecode() function can be made to
    access locations past the allocated memory, due to
    erroneously using signed numbers as array
    indexes.(CVE-2020-7067)

  - In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15
    and 7.4.x below 7.4.3, when using file upload
    functionality, if upload progress tracking is enabled,
    but session.upload_progress.cleanup is set to 0
    (disabled), and the file upload fails, the upload
    procedure would try to clean up data that does not
    exist and encounter null pointer dereference, which
    would likely lead to a crash.(CVE-2020-7062)

  - When using certain mbstring functions to convert
    multibyte encodings, in PHP versions 7.2.x below
    7.2.27, 7.3.x below 7.3.14 and 7.4.x below 7.4.2 it is
    possible to supply data that will cause function
    mbfl_filt_conv_big5_wchar to read past the allocated
    buffer. This may lead to information disclosure or
    crash.(CVE-2020-7060)

  - When using fgetss() function to read data with
    stripping tags, in PHP versions 7.2.x below 7.2.27,
    7.3.x below 7.3.14 and 7.4.x below 7.4.2 it is possible
    to supply data that will cause this function to read
    past the allocated buffer. This may lead to information
    disclosure or crash.(CVE-2020-7059)

  - University of Washington IMAP Toolkit 2007f on UNIX, as
    used in imap_open() in PHP and other products, launches
    an rsh command (by means of the imap_rimap function in
    c-client/imap4r1.c and the tcp_aopen function in
    osdep/unix/tcp_unix.c) without preventing argument
    injection, which might allow remote attackers to
    execute arbitrary OS commands if the IMAP server name
    is untrusted input (e.g., entered by a user of a web
    application) and if rsh has been replaced by a program
    with different argument semantics. For example, if rsh
    is a link to ssh (as seen on Debian and Ubuntu
    systems), then the attack can use an IMAP server name
    containing a '-oProxyCommand' argument.(CVE-2018-19518)

  - ext/standard/var_unserializer.c in PHP 5.x through
    7.1.24 allows attackers to cause a denial of service
    (application crash) via an unserialize call for the
    com, dotnet, or variant class.(CVE-2018-19396)

  - In PHP versions 7.2.x below 7.2.28, 7.3.x below 7.3.15
    and 7.4.x below 7.4.3, when creating PHAR archive using
    PharData::buildFromIterator() function, the files are
    added with default permissions (0666, or all access)
    even if the original files on the filesystem were with
    more restrictive permissions. This may result in files
    having more lax permissions than intended when such
    archive is extracted.(CVE-2020-7063)

  - In PHP versions 7.2.x below 7.2.31, 7.3.x below 7.3.18
    and 7.4.x below 7.4.6, when HTTP file uploads are
    allowed, supplying overly long filenames or field names
    could lead PHP engine to try to allocate oversized
    memory storage, hit the memory limit and stop
    processing the request, without cleaning up temporary
    files created by upload request. This potentially could
    lead to accumulation of uncleaned temporary files
    exhausting the disk space on the target
    server.(CVE-2019-11048)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1895
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?033ebeaa");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19518");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-7060");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'php imap_open Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["php-7.2.10-1.h16.eulerosv2r8",
        "php-cli-7.2.10-1.h16.eulerosv2r8",
        "php-common-7.2.10-1.h16.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
