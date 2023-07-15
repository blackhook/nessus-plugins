#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152408);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-3516",
    "CVE-2021-3517",
    "CVE-2021-3518",
    "CVE-2021-3537",
    "CVE-2021-3541"
  );

  script_name(english:"EulerOS 2.0 SP8 : libxml2 (EulerOS-SA-2021-2306)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libxml2 packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - This library allows to manipulate XML files. It
    includes supportto read, modify and write XML and HTML
    files. There is DTDs supportthis includes parsing and
    validation even with complex DtDs, eitherat parse time
    or later once the document has been modified. The
    outputcan be a simple SAX stream or an(CVE-2021-3541)

  - There's a flaw in libxml2's xmllint. An attacker who is
    able to submit a crafted file to be processed by
    xmllint could trigger a use-after-free. The greatest
    impact of this flaw is to confidentiality, integrity,
    and availability.(CVE-2021-3516)

  - There is a flaw in the xml entity encoding
    functionality of libxml2. An attacker who is able to
    supply a crafted file to be processed by an application
    linked with the affected functionality of libxml2 could
    trigger an out-of-bounds read. The most likely impact
    of this flaw is to application availability, with some
    potential impact to confidentiality and integrity if an
    attacker is able to use memory information to further
    exploit the application.(CVE-2021-3517)

  - There's a flaw in libxml2 in versions before 2.9.11. An
    attacker who is able to submit a crafted file to be
    processed by an application linked with libxml2 could
    trigger a use-after-free. The greatest impact from this
    flaw is to confidentiality, integrity, and
    availability.(CVE-2021-3518)

  - A vulnerability found in libxml2 in versions before
    2.9.11 shows that it did not propagate errors while
    parsing XML mixed content, causing a NULL dereference.
    If an untrusted XML document was parsed in recovery
    mode and post-validated, the flaw could be used to
    crash the application. The highest threat from this
    vulnerability is to system availability.(CVE-2021-3537)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2306
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28c4ed0d");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxml2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["libxml2-2.9.8-4.h16.eulerosv2r8",
        "libxml2-devel-2.9.8-4.h16.eulerosv2r8",
        "python2-libxml2-2.9.8-4.h16.eulerosv2r8",
        "python3-libxml2-2.9.8-4.h16.eulerosv2r8"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
