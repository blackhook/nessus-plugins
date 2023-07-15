#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2023-1743.
##

include('compat.inc');

if (description)
{
  script_id(175091);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/05");

  script_cve_id(
    "CVE-2017-16931",
    "CVE-2020-24977",
    "CVE-2021-3516",
    "CVE-2021-3517",
    "CVE-2021-3518",
    "CVE-2021-3537",
    "CVE-2021-3541",
    "CVE-2022-23308",
    "CVE-2022-29824",
    "CVE-2022-40303",
    "CVE-2022-40304",
    "CVE-2023-28484",
    "CVE-2023-29469"
  );

  script_name(english:"Amazon Linux AMI : libxml2 (ALAS-2023-1743)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of libxml2 installed on the remote host is prior to 2.9.1-6.6.42. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2023-1743 advisory.

  - parser.c in libxml2 before 2.9.5 mishandles parameter-entity references because the NEXTL macro calls the
    xmlParserHandlePEReference function in the case of a '%' character in a DTD name. (CVE-2017-16931)

  - GNOME project libxml2 v2.9.10 has a global buffer over-read vulnerability in xmlEncodeEntitiesInternal at
    libxml2/entities.c. The issue has been fixed in commit 50f06b3e. (CVE-2020-24977)

  - There's a flaw in libxml2's xmllint in versions before 2.9.11. An attacker who is able to submit a crafted
    file to be processed by xmllint could trigger a use-after-free. The greatest impact of this flaw is to
    confidentiality, integrity, and availability. (CVE-2021-3516)

  - There is a flaw in the xml entity encoding functionality of libxml2 in versions before 2.9.11. An attacker
    who is able to supply a crafted file to be processed by an application linked with the affected
    functionality of libxml2 could trigger an out-of-bounds read. The most likely impact of this flaw is to
    application availability, with some potential impact to confidentiality and integrity if an attacker is
    able to use memory information to further exploit the application. (CVE-2021-3517)

  - There's a flaw in libxml2 in versions before 2.9.11. An attacker who is able to submit a crafted file to
    be processed by an application linked with libxml2 could trigger a use-after-free. The greatest impact
    from this flaw is to confidentiality, integrity, and availability. (CVE-2021-3518)

  - A vulnerability found in libxml2 in versions before 2.9.11 shows that it did not propagate errors while
    parsing XML mixed content, causing a NULL dereference. If an untrusted XML document was parsed in recovery
    mode and post-validated, the flaw could be used to crash the application. The highest threat from this
    vulnerability is to system availability. (CVE-2021-3537)

  - A flaw was found in libxml2. Exponential entity expansion attack its possible bypassing all existing
    protection mechanisms and leading to denial of service. (CVE-2021-3541)

  - valid.c in libxml2 before 2.9.13 has a use-after-free of ID and IDREF attributes. (CVE-2022-23308)

  - In libxml2 before 2.9.14, several buffer handling functions in buf.c (xmlBuf*) and tree.c (xmlBuffer*)
    don't check for integer overflows. This can result in out-of-bounds memory writes. Exploitation requires a
    victim to open a crafted, multi-gigabyte XML file. Other software using libxml2's buffer functions, for
    example libxslt through 1.1.35, is affected as well. (CVE-2022-29824)

  - An issue was discovered in libxml2 before 2.10.3. When parsing a multi-gigabyte XML document with the
    XML_PARSE_HUGE parser option enabled, several integer counters can overflow. This results in an attempt to
    access an array at a negative 2GB offset, typically leading to a segmentation fault. (CVE-2022-40303)

  - An issue was discovered in libxml2 before 2.10.3. Certain invalid XML entity definitions can corrupt a
    hash table key, potentially leading to subsequent logic errors. In one case, a double-free can be
    provoked. (CVE-2022-40304)

  - In libxml2 before 2.10.4, parsing of certain invalid XSD schemas can lead to a NULL pointer dereference
    and subsequently a segfault. This occurs in xmlSchemaFixupComplexType in xmlschemas.c. (CVE-2023-28484)

  - An issue was discovered in libxml2 before 2.10.4. When hashing empty dict strings in a crafted XML
    document, xmlDictComputeFastKey in dict.c can produce non-deterministic values, leading to various logic
    and memory errors, such as a double free. This behavior occurs because there is an attempt to use the
    first byte of an empty string, and any value is possible (not solely the '\0' value). (CVE-2023-29469)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2023-1743.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2017-16931.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-24977.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3516.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3517.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3518.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3537.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3541.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-23308.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-29824.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40303.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40304.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-28484.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-29469.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libxml2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-16931");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'libxml2-2.9.1-6.6.42.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-2.9.1-6.6.42.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-debuginfo-2.9.1-6.6.42.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-debuginfo-2.9.1-6.6.42.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-devel-2.9.1-6.6.42.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-devel-2.9.1-6.6.42.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-python26-2.9.1-6.6.42.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-python26-2.9.1-6.6.42.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-python27-2.9.1-6.6.42.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-python27-2.9.1-6.6.42.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-static-2.9.1-6.6.42.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-static-2.9.1-6.6.42.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-debuginfo / libxml2-devel / etc");
}