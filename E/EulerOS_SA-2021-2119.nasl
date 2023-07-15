#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151343);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2016-9297",
    "CVE-2016-9448",
    "CVE-2017-9404",
    "CVE-2017-11335",
    "CVE-2017-16232",
    "CVE-2020-35523"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : libtiff (EulerOS-SA-2021-2119)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libtiff package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - ** RESERVED ** This candidate has been reserved by an
    organization or individual that will use it when
    announcing a new security problem. When the candidate
    has been publicized, the details for this candidate
    will be provided.(CVE-2017-16232)

  - In LibTIFF 4.0.7, a memory leak vulnerability was found
    in the function OJPEGReadHeaderInfoSecTablesQTable in
    tif_ojpeg.c, which allows attackers to cause a denial
    of service via a crafted file.(CVE-2017-9404)

  - The TIFFFetchNormalTag function in LibTiff 4.0.6 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and crash) by setting the tags
    TIFF_SETGET_C16ASCII or TIFF_SETGET_C32_ASCII to values
    that access 0-byte arrays. NOTE: this vulnerability
    exists because of an incomplete fix for
    CVE-2016-9297.(CVE-2016-9448)

  - An out-of-bounds heap read was discovered in libtiff. A
    crafted file could cause the application to crash or,
    potentially, disclose process memory.(CVE-2016-9297)

  - A heap-based buffer overflow flaw was found within
    libtiff's tiff2pdf tool. A remote attacker could
    potentially exploit this flaw to execute arbitrary code
    by tricking a user into converting a specially crafted
    file using the tiff2pdf tool.(CVE-2017-11335)

  - An integer overflow flaw was found in libtiff that
    exists in the tif_getimage.c file. This flaw allows an
    attacker to inject and execute arbitrary code when a
    user opens a crafted TIFF file. The highest threat from
    this vulnerability is to confidentiality, integrity, as
    well as system availability.(CVE-2020-35523)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2119
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4dc01ca");
  script_set_attribute(attribute:"solution", value:
"Update the affected libtiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35523");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-11335");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libtiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["libtiff-4.0.3-27.h27"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff");
}
