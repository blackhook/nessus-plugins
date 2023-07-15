#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170827);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");

  script_cve_id(
    "CVE-2021-3516",
    "CVE-2021-3517",
    "CVE-2021-3518",
    "CVE-2021-3537",
    "CVE-2021-3541",
    "CVE-2022-23308"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : libxml2 (EulerOS-SA-2023-1271)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libxml2 packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

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

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1271
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2af44228");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "libxml2-2.9.1-6.3.h30.eulerosv2r7",
  "libxml2-devel-2.9.1-6.3.h30.eulerosv2r7",
  "libxml2-python-2.9.1-6.3.h30.eulerosv2r7"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
