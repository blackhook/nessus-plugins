#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-098.
##

include('compat.inc');

if (description)
{
  script_id(173115);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id(
    "CVE-2021-3770",
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
    "CVE-2021-4173",
    "CVE-2021-4187",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2022-0128",
    "CVE-2022-0156",
    "CVE-2022-0158",
    "CVE-2022-0213",
    "CVE-2022-0261",
    "CVE-2022-0318",
    "CVE-2022-0319",
    "CVE-2022-0351",
    "CVE-2022-0359",
    "CVE-2022-0361",
    "CVE-2022-0368",
    "CVE-2022-0392",
    "CVE-2022-0393",
    "CVE-2022-0407",
    "CVE-2022-0408",
    "CVE-2022-0413",
    "CVE-2022-0417",
    "CVE-2022-0443",
    "CVE-2022-0554",
    "CVE-2022-0572",
    "CVE-2022-0629",
    "CVE-2022-0685",
    "CVE-2022-0696",
    "CVE-2022-0714",
    "CVE-2022-0729",
    "CVE-2022-0943",
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
    "CVE-2022-3705",
    "CVE-2022-4141",
    "CVE-2022-4292",
    "CVE-2023-0049"
  );
  script_xref(name:"IAVB", value:"2023-B-0018-S");

  script_name(english:"Amazon Linux 2023 : vim-common, vim-data, vim-default-editor (ALAS2023-2023-098)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-098 advisory.

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-3770, CVE-2021-3903, CVE-2021-3927,
    CVE-2021-3968, CVE-2021-3973, CVE-2021-3984, CVE-2021-4019, CVE-2021-4136, CVE-2022-0158, CVE-2022-0213)

  - vim is vulnerable to Use of Uninitialized Variable (CVE-2021-3928)

  - vim is vulnerable to Use After Free (CVE-2021-3974, CVE-2021-4069, CVE-2021-4173, CVE-2021-4187,
    CVE-2021-4192, CVE-2022-0156)

  - vim is vulnerable to Out-of-bounds Read (CVE-2021-4166, CVE-2021-4193, CVE-2022-0128)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0261, CVE-2022-0359,
    CVE-2022-0361, CVE-2022-0407, CVE-2022-0572, CVE-2022-1886, CVE-2022-1942, CVE-2022-2125, CVE-2022-2182,
    CVE-2022-2207)

  - Heap-based Buffer Overflow in vim/vim prior to 8.2. (CVE-2022-0318)

  - Out-of-bounds Read in vim/vim prior to 8.2. (CVE-2022-0319)

  - Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.
    (CVE-2022-0351)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-0368, CVE-2022-0393,
    CVE-2022-1851, CVE-2022-2126, CVE-2022-2183, CVE-2022-2206)

  - Heap-based Buffer Overflow in GitHub repository vim prior to 8.2. (CVE-2022-0392)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0408, CVE-2022-0629)

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-0413, CVE-2022-0443, CVE-2022-1898,
    CVE-2022-1968, CVE-2022-2042)

  - Heap-based Buffer Overflow GitHub repository vim/vim prior to 8.2. (CVE-2022-0417)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2. (CVE-2022-0554)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4418. (CVE-2022-0685)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.4428. (CVE-2022-0696)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4436. (CVE-2022-0714)

  - Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4440. (CVE-2022-0729)

  - Heap-based Buffer Overflow occurs in vim in GitHub repository vim/vim prior to 8.2.4563. (CVE-2022-0943)

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

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-1897, CVE-2022-2000,
    CVE-2022-2129, CVE-2022-2210)

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

  - A vulnerability was found in vim and classified as problematic. Affected by this issue is the function
    qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use
    after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this
    issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the
    affected component. The identifier of this vulnerability is VDB-212324. (CVE-2022-3705)

  - Heap based buffer overflow in vim/vim 9.0.0946 and below by allowing an attacker to CTRL-W gf in the
    expression used in the RHS of the substitute command. (CVE-2022-4141)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0882. (CVE-2022-4292)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143. (CVE-2023-0049)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-098.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3770.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3903.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3927.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3928.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3968.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3973.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3974.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3984.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4019.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4069.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4136.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4166.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4173.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4187.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4192.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4193.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0128.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0156.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0158.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0213.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0261.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0318.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0319.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0351.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0359.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0361.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0368.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0392.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0393.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0407.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0408.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0413.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0417.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0443.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0554.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0572.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0629.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0685.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0696.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0714.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0729.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0943.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1154.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1160.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1381.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1420.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1616.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1619.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1620.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1621.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1629.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1674.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1725.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1733.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1735.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1769.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1771.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1785.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1796.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1851.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1886.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1897.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1898.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1927.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1942.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1968.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2000.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2042.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2124.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2125.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2126.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2175.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2182.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2183.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2206.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2207.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2208.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2210.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2231.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2257.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2264.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2284.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2285.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2286.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2287.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2288.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2289.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2304.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2343.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2344.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2345.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2522.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2571.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2580.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2581.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2598.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2816.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2817.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2819.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2845.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2849.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2862.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2874.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2889.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2923.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2946.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2980.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2982.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3016.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3037.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3099.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3134.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3153.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3705.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4141.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4292.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0049.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update vim --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3973");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0318");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-default-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'vim-common-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-9.0.1160-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-data-9.0.1160-1.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-9.0.1160-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-default-editor-9.0.1160-1.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.1160-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-filesystem-9.0.1160-1.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.1160-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-common / vim-common-debuginfo / vim-data / etc");
}