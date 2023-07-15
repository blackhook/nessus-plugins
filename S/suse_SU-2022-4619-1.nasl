#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4619-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(169350);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2009-0316",
    "CVE-2016-1248",
    "CVE-2017-5953",
    "CVE-2017-6349",
    "CVE-2017-6350",
    "CVE-2017-17087",
    "CVE-2021-3778",
    "CVE-2021-3796",
    "CVE-2021-3872",
    "CVE-2021-3875",
    "CVE-2021-3903",
    "CVE-2021-3927",
    "CVE-2021-3928",
    "CVE-2021-3968",
    "CVE-2021-3973",
    "CVE-2021-3974",
    "CVE-2021-3984",
    "CVE-2021-4019",
    "CVE-2021-4069",
    "CVE-2021-4136",
    "CVE-2021-4166",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2021-46059",
    "CVE-2022-0128",
    "CVE-2022-0213",
    "CVE-2022-0261",
    "CVE-2022-0318",
    "CVE-2022-0319",
    "CVE-2022-0351",
    "CVE-2022-0359",
    "CVE-2022-0361",
    "CVE-2022-0392",
    "CVE-2022-0407",
    "CVE-2022-0413",
    "CVE-2022-0696",
    "CVE-2022-1381",
    "CVE-2022-1420",
    "CVE-2022-1616",
    "CVE-2022-1619",
    "CVE-2022-1620",
    "CVE-2022-1720",
    "CVE-2022-1733",
    "CVE-2022-1735",
    "CVE-2022-1771",
    "CVE-2022-1785",
    "CVE-2022-1796",
    "CVE-2022-1851",
    "CVE-2022-1897",
    "CVE-2022-1898",
    "CVE-2022-1927",
    "CVE-2022-1968",
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
    "CVE-2022-2304",
    "CVE-2022-2343",
    "CVE-2022-2344",
    "CVE-2022-2345",
    "CVE-2022-2522",
    "CVE-2022-2571",
    "CVE-2022-2580",
    "CVE-2022-2581",
    "CVE-2022-2598",
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
    "CVE-2022-3037",
    "CVE-2022-3099",
    "CVE-2022-3134",
    "CVE-2022-3153",
    "CVE-2022-3234",
    "CVE-2022-3235",
    "CVE-2022-3278",
    "CVE-2022-3296",
    "CVE-2022-3297",
    "CVE-2022-3324",
    "CVE-2022-3352",
    "CVE-2022-3705"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4619-1");
  script_xref(name:"IAVB", value:"2022-B-0049-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");

  script_name(english:"SUSE SLES12 Security Update : vim (SUSE-SU-2022:4619-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:4619-1 advisory.

  - Untrusted search path vulnerability in src/if_python.c in the Python interface in Vim before 7.2.045
    allows local users to execute arbitrary code via a Trojan horse Python file in the current working
    directory, related to a vulnerability in the PySys_SetArgv function (CVE-2008-5983), as demonstrated by an
    erroneous search path for plugin/bike.vim in bicyclerepair. (CVE-2009-0316)

  - vim before patch 8.0.0056 does not properly validate values for the 'filetype', 'syntax' and 'keymap'
    options, which may result in the execution of arbitrary code if a file with a specially crafted modeline
    is opened. (CVE-2016-1248)

  - fileio.c in Vim prior to 8.0.1263 sets the group ownership of a .swp file to the editor's primary group
    (which may be different from the group ownership of the original file), which allows local users to obtain
    sensitive information by leveraging an applicable group membership, as demonstrated by /etc/shadow owned
    by root:shadow mode 0640, but /etc/.shadow.swp owned by root:users mode 0640, a different vulnerability
    than CVE-2017-1000382. (CVE-2017-17087)

  - vim before patch 8.0.0322 does not properly validate values for tree length when handling a spell file,
    which may result in an integer overflow at a memory allocation site and a resultant buffer overflow.
    (CVE-2017-5953)

  - An integer overflow at a u_read_undo memory allocation site would occur for vim before patch 8.0.0377, if
    it does not properly validate values for tree length when reading a corrupted undo file, which may lead to
    resultant buffer overflows. (CVE-2017-6349)

  - An integer overflow at an unserialize_uep memory allocation site would occur for vim before patch
    8.0.0378, if it does not properly validate values for tree length when reading a corrupted undo file,
    which may lead to resultant buffer overflows. (CVE-2017-6350)

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-3778, CVE-2021-3872, CVE-2021-3875,
    CVE-2021-3903, CVE-2021-3927, CVE-2021-3968, CVE-2021-3973, CVE-2021-3984, CVE-2021-4019, CVE-2021-4136,
    CVE-2022-0213)

  - vim is vulnerable to Use After Free (CVE-2021-3796, CVE-2021-3974, CVE-2021-4069, CVE-2021-4192)

  - vim is vulnerable to Use of Uninitialized Variable (CVE-2021-3928)

  - vim is vulnerable to Out-of-bounds Read (CVE-2021-4166, CVE-2021-4193, CVE-2022-0128)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0261, CVE-2022-0359,
    CVE-2022-0361, CVE-2022-0407, CVE-2022-2125, CVE-2022-2182, CVE-2022-2207)

  - Heap-based Buffer Overflow in vim/vim prior to 8.2. (CVE-2022-0318)

  - Out-of-bounds Read in vim/vim prior to 8.2. (CVE-2022-0319)

  - Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.
    (CVE-2022-0351)

  - Heap-based Buffer Overflow in GitHub repository vim prior to 8.2. (CVE-2022-0392)

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-0413, CVE-2022-1898, CVE-2022-1968)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.4428. (CVE-2022-0696)

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

  - Buffer Over-read in function grab_file_name in GitHub repository vim/vim prior to 8.2.4956. This
    vulnerability is capable of crashing the software, memory modification, and possible remote execution.
    (CVE-2022-1720)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4968. (CVE-2022-1733)

  - Classic Buffer Overflow in GitHub repository vim/vim prior to 8.2.4969. (CVE-2022-1735)

  - Uncontrolled Recursion in GitHub repository vim/vim prior to 8.2.4975. (CVE-2022-1771)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2.4977. (CVE-2022-1785)

  - Use After Free in GitHub repository vim/vim prior to 8.2.4979. (CVE-2022-1796)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-1851, CVE-2022-2126,
    CVE-2022-2183, CVE-2022-2206)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-1897, CVE-2022-2129,
    CVE-2022-2210)

  - Buffer Over-read in GitHub repository vim/vim prior to 8.2. (CVE-2022-1927, CVE-2022-2124, CVE-2022-2175)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163. (CVE-2022-2208)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2. (CVE-2022-2231)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0. (CVE-2022-2257, CVE-2022-2286,
    CVE-2022-2287)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2264, CVE-2022-2284)

  - Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0. (CVE-2022-2285)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2304)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0044. (CVE-2022-2343)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0045. (CVE-2022-2344)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0046. (CVE-2022-2345)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0061. (CVE-2022-2522)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0101. (CVE-2022-2571)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0102. (CVE-2022-2580)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.0104. (CVE-2022-2581)

  - Undefined Behavior for Input to API in GitHub repository vim/vim prior to 9.0.0100. (CVE-2022-2598)

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

  - Use After Free in GitHub repository vim/vim prior to 9.0.0322. (CVE-2022-3037)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0360. (CVE-2022-3099)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0389. (CVE-2022-3134)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0404. (CVE-2022-3153)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0483. (CVE-2022-3234)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0490. (CVE-2022-3235)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0552. (CVE-2022-3278)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0577. (CVE-2022-3296)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0579. (CVE-2022-3297)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0598. (CVE-2022-3324)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0614. (CVE-2022-3352)

  - A vulnerability was found in vim and classified as problematic. Affected by this issue is the function
    qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use
    after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this
    issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the
    affected component. The identifier of this vulnerability is VDB-212324. (CVE-2022-3705)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1070955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204779");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-December/013343.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2be2817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2009-0316");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-1248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-17087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-6349");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-6350");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4136");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4193");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0213");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0351");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0359");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0392");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0407");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1420");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2175");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2231");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2257");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2304");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2344");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2345");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2522");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3278");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3297");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3324");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3352");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3705");
  script_set_attribute(attribute:"solution", value:
"Update the affected gvim, vim, vim-data and / or vim-data-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3973");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim-data-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'gvim-9.0.0814-17.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'vim-9.0.0814-17.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'vim-data-9.0.0814-17.9.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'vim-data-common-9.0.0814-17.9.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'gvim-9.0.0814-17.9.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'vim-9.0.0814-17.9.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'vim-data-9.0.0814-17.9.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'vim-data-common-9.0.0814-17.9.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'gvim-9.0.0814-17.9.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'vim-9.0.0814-17.9.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'vim-data-9.0.0814-17.9.1', 'sp':'2', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'vim-data-common-9.0.0814-17.9.1', 'sp':'2', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'gvim-9.0.0814-17.9.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'vim-9.0.0814-17.9.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'vim-data-9.0.0814-17.9.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'vim-data-common-9.0.0814-17.9.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.3']},
    {'reference':'gvim-9.0.0814-17.9.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'vim-9.0.0814-17.9.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'vim-data-9.0.0814-17.9.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'vim-data-common-9.0.0814-17.9.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gvim / vim / vim-data / vim-data-common');
}
