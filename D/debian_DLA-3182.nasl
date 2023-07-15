#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3182. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(167256);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-3927",
    "CVE-2021-3928",
    "CVE-2021-3974",
    "CVE-2021-3984",
    "CVE-2021-4019",
    "CVE-2021-4069",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2022-0213",
    "CVE-2022-0261",
    "CVE-2022-0319",
    "CVE-2022-0351",
    "CVE-2022-0359",
    "CVE-2022-0361",
    "CVE-2022-0368",
    "CVE-2022-0408",
    "CVE-2022-0413",
    "CVE-2022-0417",
    "CVE-2022-0443",
    "CVE-2022-0554",
    "CVE-2022-0572",
    "CVE-2022-0685",
    "CVE-2022-0714",
    "CVE-2022-0729",
    "CVE-2022-0943",
    "CVE-2022-1154",
    "CVE-2022-1616",
    "CVE-2022-1720",
    "CVE-2022-1851",
    "CVE-2022-1898",
    "CVE-2022-1968",
    "CVE-2022-2285",
    "CVE-2022-2304",
    "CVE-2022-2598",
    "CVE-2022-2946",
    "CVE-2022-3099",
    "CVE-2022-3134",
    "CVE-2022-3234",
    "CVE-2022-3324",
    "CVE-2022-3705"
  );
  script_xref(name:"IAVB", value:"2022-B-0049-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");

  script_name(english:"Debian DLA-3182-1 : vim - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3182 advisory.

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-3927, CVE-2021-3984, CVE-2021-4019,
    CVE-2022-0213)

  - vim is vulnerable to Use of Uninitialized Variable (CVE-2021-3928)

  - vim is vulnerable to Use After Free (CVE-2021-3974, CVE-2021-4069, CVE-2021-4192)

  - vim is vulnerable to Out-of-bounds Read (CVE-2021-4193)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0261, CVE-2022-0359,
    CVE-2022-0361, CVE-2022-0572)

  - Out-of-bounds Read in vim/vim prior to 8.2. (CVE-2022-0319)

  - Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.
    (CVE-2022-0351)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-0368, CVE-2022-1851)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0408)

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-0413, CVE-2022-0443, CVE-2022-1898,
    CVE-2022-1968)

  - Heap-based Buffer Overflow GitHub repository vim/vim prior to 8.2. (CVE-2022-0417)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2. (CVE-2022-0554)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4418. (CVE-2022-0685)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4436. (CVE-2022-0714)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4440. (CVE-2022-0729)

  - Heap-based Buffer Overflow occurs in vim in GitHub repository vim/vim prior to 8.2.4563. (CVE-2022-0943)

  - Use after free in utf_ptr2char in GitHub repository vim/vim prior to 8.2.4646. (CVE-2022-1154)

  - Use after free in append_command in GitHub repository vim/vim prior to 8.2.4895. This vulnerability is
    capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible remote execution
    (CVE-2022-1616)

  - Buffer Over-read in function grab_file_name in GitHub repository vim/vim prior to 8.2.4956. This
    vulnerability is capable of crashing the software, memory modification, and possible remote execution.
    (CVE-2022-1720)

  - Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0. (CVE-2022-2285)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2304)

  - Undefined Behavior for Input to API in GitHub repository vim/vim prior to 9.0.0100. (CVE-2022-2598)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0246. (CVE-2022-2946)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0360. (CVE-2022-3099)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0389. (CVE-2022-3134)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0483. (CVE-2022-3234)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0598. (CVE-2022-3324)

  - A vulnerability was found in vim and classified as problematic. Affected by this issue is the function
    qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use
    after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this
    issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the
    affected component. The identifier of this vulnerability is VDB-212324. (CVE-2022-3705)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/vim");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3182");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3927");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3928");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3984");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4019");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4069");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4192");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4193");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0213");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0261");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0319");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0351");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0359");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0361");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0368");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0408");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0413");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0417");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0443");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0554");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0572");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0714");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0729");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0943");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1154");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1616");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1720");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1851");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1968");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2285");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2304");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3099");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3134");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3234");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3324");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3705");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/vim");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vim packages.

For Debian 10 buster, these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2304");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xxd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'vim', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'vim-athena', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'vim-common', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'vim-doc', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'vim-gtk', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'vim-gtk3', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'vim-gui-common', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'vim-nox', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'vim-runtime', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'vim-tiny', 'reference': '2:8.1.0875-5+deb10u3'},
    {'release': '10.0', 'prefix': 'xxd', 'reference': '2:8.1.0875-5+deb10u3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vim / vim-athena / vim-common / vim-doc / vim-gtk / vim-gtk3 / etc');
}
