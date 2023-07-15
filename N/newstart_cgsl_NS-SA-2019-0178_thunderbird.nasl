#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0178. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128698);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-18511",
    "CVE-2019-5798",
    "CVE-2019-7317",
    "CVE-2019-9797",
    "CVE-2019-9800",
    "CVE-2019-9817",
    "CVE-2019-9819",
    "CVE-2019-9820",
    "CVE-2019-11691",
    "CVE-2019-11692",
    "CVE-2019-11693",
    "CVE-2019-11698",
    "CVE-2019-11703",
    "CVE-2019-11704",
    "CVE-2019-11705",
    "CVE-2019-11706",
    "CVE-2019-11707",
    "CVE-2019-11708"
  );
  script_bugtraq_id(107009);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2019-0458");

  script_name(english:"NewStart CGSL MAIN 4.06 : thunderbird Multiple Vulnerabilities (NS-SA-2019-0178)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has thunderbird packages installed that are affected by
multiple vulnerabilities:

  - Lack of correct bounds checking in Skia in Google Chrome
    prior to 73.0.3683.75 allowed a remote attacker to
    perform an out of bounds memory read via a crafted HTML
    page. (CVE-2019-5798)

  - Cross-origin images can be read from a canvas element in
    violation of the same-origin policy using the
    transferFromImageBitmap method. *Note: This only affects
    Firefox 65. Previous versions are unaffected.*. This
    vulnerability affects Firefox < 65.0.1. (CVE-2018-18511)

  - Cross-origin images can be read in violation of the
    same-origin policy by exporting an image after using
    createImageBitmap to read the image and then rendering
    the resulting bitmap image within a canvas element. This
    vulnerability affects Firefox < 66. (CVE-2019-9797)

  - A flaw in Thunderbird's implementation of iCal causes a
    stack buffer overflow in icalrecur_add_bydayrules when
    processing certain email messages, resulting in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7.1. (CVE-2019-11705)

  - A flaw in Thunderbird's implementation of iCal causes a
    type confusion in icaltimezone_get_vtimezone_properties
    when processing certain email messages, resulting in a
    crash. This vulnerability affects Thunderbird < 60.7.1.
    (CVE-2019-11706)

  - Insufficient vetting of parameters passed with the
    Prompt:Open IPC message between child and parent
    processes can result in the non-sandboxed parent process
    opening web content chosen by a compromised child
    process. When combined with additional vulnerabilities
    this could result in executing arbitrary code on the
    user's computer. This vulnerability affects Firefox ESR
    < 60.7.2, Firefox < 67.0.4, and Thunderbird < 60.7.2.
    (CVE-2019-11708)

  - A type confusion vulnerability can occur when
    manipulating JavaScript objects due to issues in
    Array.pop. This can allow for an exploitable crash. We
    are aware of targeted attacks in the wild abusing this
    flaw. This vulnerability affects Firefox ESR < 60.7.1,
    Firefox < 67.0.3, and Thunderbird < 60.7.2.
    (CVE-2019-11707)

  - A flaw in Thunderbird's implementation of iCal causes a
    heap buffer overflow in icalmemory_strdup_and_dequote
    when processing certain email messages, resulting in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7.1. (CVE-2019-11704)

  - png_image_free in png.c in libpng 1.6.x before 1.6.37
    has a use-after-free because png_image_free_function is
    called under png_safe_execute. (CVE-2019-7317)

  - A flaw in Thunderbird's implementation of iCal causes a
    heap buffer overflow in parser_get_next_char when
    processing certain email messages, resulting in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7.1. (CVE-2019-11703)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0178");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11708");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.06": [
    "thunderbird-60.8.0-1.el6.centos",
    "thunderbird-debuginfo-60.8.0-1.el6.centos"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
