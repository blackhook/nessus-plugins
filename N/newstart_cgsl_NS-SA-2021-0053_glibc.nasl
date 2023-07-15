##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0053. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147282);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2016-6261",
    "CVE-2016-6263",
    "CVE-2017-14062",
    "CVE-2017-15670",
    "CVE-2017-15804",
    "CVE-2017-16997",
    "CVE-2017-17426",
    "CVE-2017-18269",
    "CVE-2017-1000408",
    "CVE-2017-1000409",
    "CVE-2018-11236",
    "CVE-2018-11237",
    "CVE-2018-19591",
    "CVE-2018-1000001",
    "CVE-2019-9169",
    "CVE-2020-10029"
  );
  script_bugtraq_id(
    92070,
    101521,
    101535,
    102228,
    102525,
    102913,
    102914,
    104255,
    104256,
    106037,
    107160
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : glibc Multiple Vulnerabilities (NS-SA-2021-0053)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has glibc packages installed that are affected by multiple
vulnerabilities:

  - The idna_to_ascii_4i function in lib/idna.c in libidn before 1.33 allows context-dependent attackers to
    cause a denial of service (out-of-bounds read and crash) via 64 bytes of input. (CVE-2016-6261)

  - The stringprep_utf8_nfkc_normalize function in lib/nfkc.c in libidn before 1.33 allows context-dependent
    attackers to cause a denial of service (out-of-bounds read and crash) via crafted UTF-8 data.
    (CVE-2016-6263)

  - A memory leak in glibc 2.1.1 (released on May 24, 1999) can be reached and amplified through the
    LD_HWCAP_MASK environment variable. Please note that many versions of glibc are not vulnerable to this
    issue if patched for CVE-2017-1000366. (CVE-2017-1000408)

  - A buffer overflow in glibc 2.5 (released on September 29, 2006) and can be triggered through the
    LD_LIBRARY_PATH environment variable. Please note that many versions of glibc are not vulnerable to this
    issue if patched for CVE-2017-1000366. (CVE-2017-1000409)

  - Integer overflow in the decode_digit function in puny_decode.c in Libidn2 before 2.0.4 allows remote
    attackers to cause a denial of service or possibly have unspecified other impact. (CVE-2017-14062)

  - The GNU C Library (aka glibc or libc6) before 2.27 contains an off-by-one error leading to a heap-based
    buffer overflow in the glob function in glob.c, related to the processing of home directories using the ~
    operator followed by a long string. (CVE-2017-15670)

  - The glob function in glob.c in the GNU C Library (aka glibc or libc6) before 2.27 contains a buffer
    overflow during unescaping of user names with the ~ operator. (CVE-2017-15804)

  - elf/dl-load.c in the GNU C Library (aka glibc or libc6) 2.19 through 2.26 mishandles RPATH and RUNPATH
    containing $ORIGIN for a privileged (setuid or AT_SECURE) program, which allows local users to gain
    privileges via a Trojan horse library in the current working directory, related to the fillin_rpath and
    decompose_rpath functions. This is associated with misinterpretion of an empty RPATH/RUNPATH token as the
    ./ directory. NOTE: this configuration of RPATH/RUNPATH for a privileged program is apparently very
    uncommon; most likely, no such program is shipped with any common Linux distribution. (CVE-2017-16997)

  - The malloc function in the GNU C Library (aka glibc or libc6) 2.26 could return a memory block that is too
    small if an attempt is made to allocate an object whose size is close to SIZE_MAX, potentially leading to
    a subsequent heap overflow. This occurs because the per-thread cache (aka tcache) feature enables a code
    path that lacks an integer overflow check. (CVE-2017-17426)

  - An SSE2-optimized memmove implementation for i386 in sysdeps/i386/i686/multiarch/memcpy-sse2-unaligned.S
    in the GNU C Library (aka glibc or libc6) 2.21 through 2.27 does not correctly perform the overlapping
    memory check if the source memory range spans the middle of the address space, resulting in corrupt data
    being produced by the copy operation. This may disclose information to context-dependent attackers, or
    result in a denial of service, or, possibly, code execution. (CVE-2017-18269)

  - In glibc 2.26 and earlier there is confusion in the usage of getcwd() by realpath() which can be used to
    write before the destination buffer leading to a buffer underflow and potential code execution.
    (CVE-2018-1000001)

  - stdlib/canonicalize.c in the GNU C Library (aka glibc or libc6) 2.27 and earlier, when processing very
    long pathname arguments to the realpath function, could encounter an integer overflow on 32-bit
    architectures, leading to a stack-based buffer overflow and, potentially, arbitrary code execution.
    (CVE-2018-11236)

  - An AVX-512-optimized implementation of the mempcpy function in the GNU C Library (aka glibc or libc6) 2.27
    and earlier may write data beyond the target buffer, leading to a buffer overflow in
    __mempcpy_avx512_no_vzeroupper. (CVE-2018-11237)

  - In the GNU C Library (aka glibc or libc6) through 2.28, attempting to resolve a crafted hostname via
    getaddrinfo() leads to the allocation of a socket descriptor that is not closed. This is related to the
    if_nametoindex() function. (CVE-2018-19591)

  - In the GNU C Library (aka glibc or libc6) through 2.29, proceed_next_node in posix/regexec.c has a heap-
    based buffer over-read via an attempted case-insensitive regular-expression match. (CVE-2019-9169)

  - The GNU C Library (aka glibc or libc6) before 2.32 could overflow an on-stack buffer during range
    reduction if an input to an 80-bit long double function contains a non-canonical bit pattern, a seen when
    passing a 0x5d414141414141410000 value to sinl on x86 targets. This is related to
    sysdeps/ieee754/ldbl-96/e_rem_pio2l.c. (CVE-2020-10029)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0053");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16997");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-9169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc realpath() Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'compat-libpthread-nonshared-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-all-langpacks-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-benchtests-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-common-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-debuginfo-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-debuginfo-common-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-devel-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-headers-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-aa-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-af-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-agr-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ak-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-am-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-an-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-anp-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ar-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-as-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ast-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ayc-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-az-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-be-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-bem-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ber-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-bg-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-bhb-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-bho-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-bi-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-bn-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-bo-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-br-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-brx-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-bs-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-byn-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ca-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ce-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-chr-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-cmn-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-crh-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-cs-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-csb-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-cv-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-cy-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-da-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-de-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-doi-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-dsb-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-dv-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-dz-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-el-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-en-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-eo-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-es-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-et-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-eu-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-fa-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ff-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-fi-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-fil-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-fo-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-fr-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-fur-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-fy-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ga-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-gd-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-gez-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-gl-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-gu-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-gv-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ha-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-hak-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-he-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-hi-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-hif-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-hne-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-hr-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-hsb-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ht-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-hu-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-hy-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ia-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-id-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ig-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ik-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-is-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-it-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-iu-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ja-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ka-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-kab-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-kk-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-kl-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-km-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-kn-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ko-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-kok-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ks-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ku-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-kw-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ky-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-lb-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-lg-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-li-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-lij-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ln-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-lo-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-lt-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-lv-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-lzh-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mag-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mai-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mfe-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mg-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mhr-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mi-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-miq-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mjw-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mk-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ml-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mn-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mni-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mr-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ms-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-mt-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-my-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-nan-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-nb-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-nds-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ne-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-nhn-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-niu-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-nl-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-nn-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-nr-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-nso-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-oc-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-om-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-or-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-os-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-pa-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-pap-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-pl-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ps-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-pt-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-quz-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-raj-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ro-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ru-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-rw-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sa-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sah-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sat-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sc-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sd-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-se-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sgs-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-shn-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-shs-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-si-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sid-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sk-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sl-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sm-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-so-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sq-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sr-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ss-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-st-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sv-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-sw-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-szl-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ta-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-tcy-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-te-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-tg-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-th-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-the-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ti-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-tig-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-tk-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-tl-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-tn-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-to-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-tpi-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-tr-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ts-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-tt-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ug-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-uk-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-unm-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ur-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-uz-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-ve-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-vi-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-wa-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-wae-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-wal-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-wo-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-xh-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-yi-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-yo-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-yue-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-yuw-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-zh-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-langpack-zu-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-locale-source-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-minimal-langpack-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-nss-devel-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-static-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'glibc-utils-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'libnsl-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'nscd-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'nss_db-2.28-101.el8.cgslv6_2.0.2.g1504d257',
    'nss_hesiod-2.28-101.el8.cgslv6_2.0.2.g1504d257'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc');
}
