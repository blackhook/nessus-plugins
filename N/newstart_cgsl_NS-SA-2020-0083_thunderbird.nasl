##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0083. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144001);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id(
    "CVE-2020-12398",
    "CVE-2020-12405",
    "CVE-2020-12406",
    "CVE-2020-12410",
    "CVE-2020-12417",
    "CVE-2020-12418",
    "CVE-2020-12419",
    "CVE-2020-12420",
    "CVE-2020-12421",
    "CVE-2020-15646"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : thunderbird Multiple Vulnerabilities (NS-SA-2020-0083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - Mozilla developers reported memory safety bugs present in Firefox 76 and Firefox ESR 68.8. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and
    Firefox ESR < 68.9. (CVE-2020-12410)

  - Mozilla Developer Iain Ireland discovered a missing type check during unboxed objects removal, resulting
    in a crash. We presume that with enough effort that it could be exploited to run arbitrary code. This
    vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and Firefox ESR < 68.9. (CVE-2020-12406)

  - When browsing a malicious page, a race condition in our SharedWorkerService could occur and lead to a
    potentially exploitable crash. This vulnerability affects Thunderbird < 68.9.0, Firefox < 77, and Firefox
    ESR < 68.9. (CVE-2020-12405)

  - If Thunderbird is configured to use STARTTLS for an IMAP server, and the server sends a PREAUTH response,
    then Thunderbird will continue with an unencrypted connection, causing email data to be sent without
    protection. This vulnerability affects Thunderbird < 68.9.0. (CVE-2020-12398)

  - Due to confusion about ValueTags on JavaScript Objects, an object may pass through the type barrier,
    resulting in memory corruption and a potentially exploitable crash. *Note: this issue only affects Firefox
    on ARM64 platforms.* This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and Thunderbird <
    68.10.0. (CVE-2020-12417)

  - Manipulating individual parts of a URL object could have caused an out-of-bounds read, leaking process
    memory to malicious JavaScript. This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and
    Thunderbird < 68.10.0. (CVE-2020-12418)

  - When processing callbacks that occurred during window flushing in the parent process, the associated
    window may die; causing a use-after-free condition. This could have led to memory corruption and a
    potentially exploitable crash. This vulnerability affects Firefox ESR < 68.10, Firefox < 78, and
    Thunderbird < 68.10.0. (CVE-2020-12419)

  - When trying to connect to a STUN server, a race condition could have caused a use-after-free of a pointer,
    leading to memory corruption and a potentially exploitable crash. This vulnerability affects Firefox ESR <
    68.10, Firefox < 78, and Thunderbird < 68.10.0. (CVE-2020-12420)

  - When performing add-on updates, certificate chains terminating in non-built-in-roots were rejected (even
    if they were legitimately added by an administrator.) This could have caused add-ons to become out-of-date
    silently without notification to the user. This vulnerability affects Firefox ESR < 68.10, Firefox < 78,
    and Thunderbird < 68.10.0. (CVE-2020-12421)

  - If an attacker intercepts Thunderbird's initial attempt to perform automatic account setup using the
    Microsoft Exchange autodiscovery mechanism, and the attacker sends a crafted response, then Thunderbird
    sends username and password over https to a server controlled by the attacker. This vulnerability affects
    Thunderbird < 68.10.0. (CVE-2020-15646)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0083");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12420");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'thunderbird-68.10.0-1.el7.centos',
    'thunderbird-debuginfo-68.10.0-1.el7.centos'
  ],
  'CGSL MAIN 5.04': [
    'thunderbird-68.10.0-1.el7.centos',
    'thunderbird-debuginfo-68.10.0-1.el7.centos'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}
