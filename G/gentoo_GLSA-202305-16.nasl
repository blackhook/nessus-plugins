#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-16.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(175057);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id(
    "CVE-2022-1154",
    "CVE-2022-1160",
    "CVE-2022-1381",
    "CVE-2022-1420",
    "CVE-2022-1616",
    "CVE-2022-1619",
    "CVE-2022-1620",
    "CVE-2022-1621",
    "CVE-2022-1629",
    "CVE-2022-1674",
    "CVE-2022-1720",
    "CVE-2022-1725",
    "CVE-2022-1733",
    "CVE-2022-1735",
    "CVE-2022-1769",
    "CVE-2022-1771",
    "CVE-2022-1785",
    "CVE-2022-1796",
    "CVE-2022-1851",
    "CVE-2022-1886",
    "CVE-2022-1897",
    "CVE-2022-1898",
    "CVE-2022-1927",
    "CVE-2022-1942",
    "CVE-2022-1968",
    "CVE-2022-2000",
    "CVE-2022-2042",
    "CVE-2022-2124",
    "CVE-2022-2125",
    "CVE-2022-2126",
    "CVE-2022-2129",
    "CVE-2022-2175",
    "CVE-2022-2182",
    "CVE-2022-2183",
    "CVE-2022-2206",
    "CVE-2022-2207",
    "CVE-2022-2208",
    "CVE-2022-2210",
    "CVE-2022-2231",
    "CVE-2022-2257",
    "CVE-2022-2264",
    "CVE-2022-2284",
    "CVE-2022-2285",
    "CVE-2022-2286",
    "CVE-2022-2287",
    "CVE-2022-2288",
    "CVE-2022-2289",
    "CVE-2022-2304",
    "CVE-2022-2343",
    "CVE-2022-2344",
    "CVE-2022-2345",
    "CVE-2022-2522",
    "CVE-2022-2816",
    "CVE-2022-2817",
    "CVE-2022-2819",
    "CVE-2022-2845",
    "CVE-2022-2849",
    "CVE-2022-2862",
    "CVE-2022-2874",
    "CVE-2022-2889",
    "CVE-2022-2923",
    "CVE-2022-2946",
    "CVE-2022-2980",
    "CVE-2022-2982",
    "CVE-2022-3016",
    "CVE-2022-3099",
    "CVE-2022-3134",
    "CVE-2022-3153",
    "CVE-2022-3234",
    "CVE-2022-3235",
    "CVE-2022-3256",
    "CVE-2022-3278",
    "CVE-2022-3296",
    "CVE-2022-3297",
    "CVE-2022-3324",
    "CVE-2022-3352",
    "CVE-2022-3491",
    "CVE-2022-3520",
    "CVE-2022-3591",
    "CVE-2022-3705",
    "CVE-2022-4141",
    "CVE-2022-4292",
    "CVE-2022-4293",
    "CVE-2022-47024",
    "CVE-2023-0049",
    "CVE-2023-0051",
    "CVE-2023-0054"
  );

  script_name(english:"GLSA-202305-16 : Vim, gVim: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-16 (Vim, gVim: Multiple Vulnerabilities)

  - Use after free in utf_ptr2char in GitHub repository vim/vim prior to 8.2.4646. (CVE-2022-1154)

  - heap buffer overflow in get_one_sourceline in GitHub repository vim/vim prior to 8.2.4647. (CVE-2022-1160)

  - global heap buffer overflow in skip_range in GitHub repository vim/vim prior to 8.2.4763. This
    vulnerability is capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible
    remote execution (CVE-2022-1381)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4774. (CVE-2022-1420)

  - Use after free in append_command in GitHub repository vim/vim prior to 8.2.4895. This vulnerability is
    capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible remote execution
    (CVE-2022-1616)

  - Heap-based Buffer Overflow in function cmdline_erase_chars in GitHub repository vim/vim prior to 8.2.4899.
    This vulnerabilities are capable of crashing software, modify memory, and possible remote execution
    (CVE-2022-1619)

  - NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 in GitHub repository vim/vim
    prior to 8.2.4901. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 allows
    attackers to cause a denial of service (application crash) via a crafted input. (CVE-2022-1620)

  - Heap buffer overflow in vim_strncpy find_word in GitHub repository vim/vim prior to 8.2.4919. This
    vulnerability is capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible
    remote execution (CVE-2022-1621)

  - Buffer Over-read in function find_next_quote in GitHub repository vim/vim prior to 8.2.4925. This
    vulnerabilities are capable of crashing software, Modify Memory, and possible remote execution
    (CVE-2022-1629)

  - NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 in GitHub repository vim/vim
    prior to 8.2.4938. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2733 allows
    attackers to cause a denial of service (application crash) via a crafted input. (CVE-2022-1674)

  - Buffer Over-read in function grab_file_name in GitHub repository vim/vim prior to 8.2.4956. This
    vulnerability is capable of crashing the software, memory modification, and possible remote execution.
    (CVE-2022-1720)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.4959. (CVE-2022-1725)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4968. (CVE-2022-1733)

  - Classic Buffer Overflow in GitHub repository vim/vim prior to 8.2.4969. (CVE-2022-1735)

  - Buffer Over-read in GitHub repository vim/vim prior to 8.2.4974. (CVE-2022-1769)

  - Uncontrolled Recursion in GitHub repository vim/vim prior to 8.2.4975. (CVE-2022-1771)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.4977. (CVE-2022-1785)

  - Use After Free in GitHub repository vim/vim prior to 8.2.4979. (CVE-2022-1796)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-1851, CVE-2022-2126,
    CVE-2022-2183, CVE-2022-2206)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-1886, CVE-2022-1942,
    CVE-2022-2125, CVE-2022-2182, CVE-2022-2207)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-1897, CVE-2022-2000,
    CVE-2022-2129, CVE-2022-2210)

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-1898, CVE-2022-1968, CVE-2022-2042)

  - Buffer Over-read in GitHub repository vim/vim prior to 8.2. (CVE-2022-1927, CVE-2022-2124, CVE-2022-2175)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163. (CVE-2022-2208)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2. (CVE-2022-2231)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0. (CVE-2022-2257, CVE-2022-2286,
    CVE-2022-2287)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2264, CVE-2022-2284)

  - Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0. (CVE-2022-2285)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 9.0. (CVE-2022-2288)

  - Use After Free in GitHub repository vim/vim prior to 9.0. (CVE-2022-2289)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2304)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0044. (CVE-2022-2343)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0045. (CVE-2022-2344)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0046. (CVE-2022-2345)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0061. (CVE-2022-2522)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.0212. (CVE-2022-2816)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0213. (CVE-2022-2817)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0211. (CVE-2022-2819)

  - Buffer Over-read in GitHub repository vim/vim prior to 9.0.0218. (CVE-2022-2845)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0220. (CVE-2022-2849)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0221. (CVE-2022-2862)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0224. (CVE-2022-2874)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0225. (CVE-2022-2889)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0240. (CVE-2022-2923)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0246. (CVE-2022-2946)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0259. (CVE-2022-2980)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0260. (CVE-2022-2982)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0286. (CVE-2022-3016)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0360. (CVE-2022-3099)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0389. (CVE-2022-3134)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0404. (CVE-2022-3153)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0483. (CVE-2022-3234)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0490. (CVE-2022-3235)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0530. (CVE-2022-3256)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0552. (CVE-2022-3278)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0577. (CVE-2022-3296)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0579. (CVE-2022-3297)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0598. (CVE-2022-3324)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0614. (CVE-2022-3352)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0742. (CVE-2022-3491)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0765. (CVE-2022-3520)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0789. (CVE-2022-3591)

  - A vulnerability was found in vim and classified as problematic. Affected by this issue is the function
    qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use
    after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this
    issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the
    affected component. The identifier of this vulnerability is VDB-212324. (CVE-2022-3705)

  - Heap based buffer overflow in vim/vim 9.0.0946 and below by allowing an attacker to CTRL-W gf in the
    expression used in the RHS of the substitute command. (CVE-2022-4141)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0882. (CVE-2022-4292)

  - Floating Point Comparison with Incorrect Operator in GitHub repository vim/vim prior to 9.0.0804.
    (CVE-2022-4293)

  - A null pointer dereference issue was discovered in function gui_x11_create_blank_mouse in gui_x11.c in vim
    8.1.2269 thru 9.0.0339 allows attackers to cause denial of service or other unspecified impacts.
    (CVE-2022-47024)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143. (CVE-2023-0049)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1144. (CVE-2023-0051)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1145. (CVE-2023-0054)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-16");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=851231");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=861092");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=869359");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=879257");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=883681");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=889730");
  script_set_attribute(attribute:"solution", value:
"All Vim users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-editors/vim-9.0.1157
        
All gVim users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-editors/gvim-9.0.1157
        
All vim-core users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-editors/vim-core-9.0.1157");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2345");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3520");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vim-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'app-editors/gvim',
    'unaffected' : make_list("ge 9.0.1157"),
    'vulnerable' : make_list("lt 9.0.1157")
  },
  {
    'name' : 'app-editors/vim',
    'unaffected' : make_list("ge 9.0.1157"),
    'vulnerable' : make_list("lt 9.0.1157")
  },
  {
    'name' : 'app-editors/vim-core',
    'unaffected' : make_list("ge 9.0.1157"),
    'vulnerable' : make_list("lt 9.0.1157")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Vim / gVim');
}
