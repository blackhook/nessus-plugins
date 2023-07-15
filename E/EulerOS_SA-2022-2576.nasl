#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165967);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/10");

  script_cve_id(
    "CVE-2018-5727",
    "CVE-2018-18088",
    "CVE-2018-20845",
    "CVE-2019-12973",
    "CVE-2022-1122"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : openjpeg2 (EulerOS-SA-2022-2576)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openjpeg2 package installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - OpenJPEG 2.3.0 has a NULL pointer dereference for 'red' in the imagetopnm function of jp2/convert.c
    (CVE-2018-18088)

  - Division-by-zero vulnerabilities in the functions pi_next_pcrl, pi_next_cprl, and pi_next_rpcl in
    openmj2/pi.c in OpenJPEG through 2.3.0 allow remote attackers to cause a denial of service (application
    crash). (CVE-2018-20845)

  - In OpenJPEG 2.3.0, there is an integer overflow vulnerability in the opj_t1_encode_cblks function
    (openjp2/t1.c). Remote attackers could leverage this vulnerability to cause a denial of service via a
    crafted bmp file. (CVE-2018-5727)

  - In OpenJPEG 2.3.1, there is excessive iteration in the opj_t1_encode_cblks function of openjp2/t1.c.
    Remote attackers could leverage this vulnerability to cause a denial of service via a crafted bmp file.
    This issue is similar to CVE-2018-6616. (CVE-2019-12973)

  - A flaw was found in the opj2_decompress program in openjpeg2 2.4.0 in the way it handles an input
    directory with a large number of files. When it fails to allocate a buffer to store the filenames of the
    input directory, it calls free() on an uninitialized pointer, leading to a segmentation fault and a denial
    of service. (CVE-2022-1122)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2576
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6b74985");
  script_set_attribute(attribute:"solution", value:
"Update the affected openjpeg2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1122");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-5727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openjpeg2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "openjpeg2-2.3.0-9.h12.eulerosv2r8"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg2");
}
