#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0157. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154526);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2019-15691",
    "CVE-2019-15692",
    "CVE-2019-15693",
    "CVE-2019-15694",
    "CVE-2019-15695"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : tigervnc Multiple Vulnerabilities (NS-SA-2021-0157)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has tigervnc packages installed that are affected
by multiple vulnerabilities:

  - TigerVNC version prior to 1.10.1 is vulnerable to stack use-after-return, which occurs due to incorrect
    usage of stack memory in ZRLEDecoder. If decoding routine would throw an exception, ZRLEDecoder may try to
    access stack variable, which has been already freed during the process of stack unwinding. Exploitation of
    this vulnerability could potentially result into remote code execution. This attack appear to be
    exploitable via network connectivity. (CVE-2019-15691)

  - TigerVNC version prior to 1.10.1 is vulnerable to heap buffer overflow. Vulnerability could be triggered
    from CopyRectDecoder due to incorrect value checks. Exploitation of this vulnerability could potentially
    result into remote code execution. This attack appear to be exploitable via network connectivity.
    (CVE-2019-15692)

  - TigerVNC version prior to 1.10.1 is vulnerable to heap buffer overflow, which occurs in
    TightDecoder::FilterGradient. Exploitation of this vulnerability could potentially result into remote code
    execution. This attack appear to be exploitable via network connectivity. (CVE-2019-15693)

  - TigerVNC version prior to 1.10.1 is vulnerable to heap buffer overflow, which could be triggered from
    DecodeManager::decodeRect. Vulnerability occurs due to the signdness error in processing MemOutStream.
    Exploitation of this vulnerability could potentially result into remote code execution. This attack appear
    to be exploitable via network connectivity. (CVE-2019-15694)

  - TigerVNC version prior to 1.10.1 is vulnerable to stack buffer overflow, which could be triggered from
    CMsgReader::readSetCursor. This vulnerability occurs due to insufficient sanitization of PixelFormat.
    Since remote attacker can choose offset from start of the buffer to start writing his values, exploitation
    of this vulnerability could potentially result into remote code execution. This attack appear to be
    exploitable via network connectivity. (CVE-2019-15695)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0157");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-15691");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-15692");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-15693");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-15694");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-15695");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL tigervnc packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:tigervnc-server-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:tigervnc-server-module");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'tigervnc-1.8.0-22.el7',
    'tigervnc-icons-1.8.0-22.el7',
    'tigervnc-license-1.8.0-22.el7',
    'tigervnc-server-1.8.0-22.el7',
    'tigervnc-server-applet-1.8.0-22.el7',
    'tigervnc-server-minimal-1.8.0-22.el7',
    'tigervnc-server-module-1.8.0-22.el7'
  ],
  'CGSL MAIN 5.05': [
    'tigervnc-1.8.0-22.el7',
    'tigervnc-icons-1.8.0-22.el7',
    'tigervnc-license-1.8.0-22.el7',
    'tigervnc-server-1.8.0-22.el7',
    'tigervnc-server-applet-1.8.0-22.el7',
    'tigervnc-server-minimal-1.8.0-22.el7',
    'tigervnc-server-module-1.8.0-22.el7'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tigervnc');
}
