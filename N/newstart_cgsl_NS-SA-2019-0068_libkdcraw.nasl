#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0068. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127269);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-5800",
    "CVE-2018-5801",
    "CVE-2018-5802",
    "CVE-2018-5805",
    "CVE-2018-5806"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : libkdcraw Multiple Vulnerabilities (NS-SA-2019-0068)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has libkdcraw packages installed that are affected
by multiple vulnerabilities:

  - LibRaw is vulnerable to stack-based buffer overflow in
    internal/dcraw_common.cpp:quicktake_100_load_raw()
    function when processing specially-crafted RAW data. An
    attacker could potentially use this flaw to cause an
    arbitrary code execution or denial of service.
    (CVE-2018-5805)

  - A NULL pointer dereference flaw was found in the way
    LibRaw processed images. An attacker could potentially
    use this flaw to crash applications using LibRaw by
    tricking them into processing crafted images.
    (CVE-2018-5801)

  - An out-of-bounds read flaw was found in the way LibRaw
    processed images. An attacker could potentially use this
    flaw to crash applications using LibRaw by tricking them
    into processing crafted images. (CVE-2018-5802)

  - A NULL pointer dereference vulnerability in
    internal/dcraw_common.cpp:leaf_hdr_load_raw() function
    was found in LibRaw. A user can cause a denial of
    service when processing specially-crafted RAW data.
    (CVE-2018-5806)

  - A heap-based out-of-bounds access flaw was found in the
    way LibRaw processed images. An attacker could
    potentially use this flaw to crash applications using
    LibRaw by tricking them into processing crafted images.
    (CVE-2018-5800)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0068");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libkdcraw packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "libkdcraw-4.10.5-5.el7",
    "libkdcraw-debuginfo-4.10.5-5.el7",
    "libkdcraw-devel-4.10.5-5.el7"
  ],
  "CGSL MAIN 5.04": [
    "libkdcraw-4.10.5-5.el7",
    "libkdcraw-debuginfo-4.10.5-5.el7",
    "libkdcraw-devel-4.10.5-5.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libkdcraw");
}
