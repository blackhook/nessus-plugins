##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4444.
##

include('compat.inc');

if (description)
{
  script_id(142780);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-1751", "CVE-2020-1752", "CVE-2020-10029");

  script_name(english:"Oracle Linux 8 : glibc (ELSA-2020-4444)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4444 advisory.

  - A use-after-free vulnerability introduced in glibc upstream version 2.14 was found in the way the tilde
    expansion was carried out. Directory paths containing an initial tilde followed by a valid username were
    affected by this issue. A local attacker could exploit this flaw by creating a specially crafted path
    that, when processed by the glob function, would potentially lead to arbitrary code execution. This was
    fixed in version 2.32. (CVE-2020-1752)

  - An out-of-bounds write vulnerability was found in glibc before 2.31 when handling signal trampolines on
    PowerPC. Specifically, the backtrace function did not properly check the array bounds when storing the
    frame address, resulting in a denial of service or potential code execution. The highest threat from this
    vulnerability is to system availability. (CVE-2020-1751)

  - The GNU C Library (aka glibc or libc6) before 2.32 could overflow an on-stack buffer during range
    reduction if an input to an 80-bit long double function contains a non-canonical bit pattern, a seen when
    passing a 0x5d414141414141410000 value to sinl on x86 targets. This is related to
    sysdeps/ieee754/ldbl-96/e_rem_pio2l.c. (CVE-2020-10029)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4444.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1751");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:compat-libpthread-nonshared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-benchtests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-agr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-anp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ayc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bhb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bho");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-brx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-byn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-chr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-cmn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-crh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-cv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-doi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-iu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ky");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-li");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ln");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lzh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mfe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mhr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-miq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mjw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nhn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-niu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-pap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-quz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-raj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-shn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-shs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-so");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tcy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-the");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-to");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-unm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-wa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-wae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-wal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-wo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-yi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-yo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-yue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-yuw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-minimal-langpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss_db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss_hesiod");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'compat-libpthread-nonshared-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'compat-libpthread-nonshared-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-2.28-127.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'glibc-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-all-langpacks-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-all-langpacks-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-benchtests-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-benchtests-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-common-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-common-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-devel-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-devel-2.28-127.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'glibc-devel-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-headers-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-headers-2.28-127.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'glibc-headers-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-aa-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-aa-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-af-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-af-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-agr-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-agr-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ak-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ak-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-am-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-am-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-an-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-an-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-anp-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-anp-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ar-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ar-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-as-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-as-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ast-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ast-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ayc-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ayc-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-az-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-az-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-be-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-be-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-bem-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-bem-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ber-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ber-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-bg-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-bg-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-bhb-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-bhb-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-bho-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-bho-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-bi-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-bi-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-bn-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-bn-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-bo-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-bo-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-br-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-br-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-brx-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-brx-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-bs-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-bs-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-byn-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-byn-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ca-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ca-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ce-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ce-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-chr-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-chr-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-cmn-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-cmn-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-crh-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-crh-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-cs-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-cs-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-csb-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-csb-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-cv-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-cv-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-cy-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-cy-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-da-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-da-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-de-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-de-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-doi-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-doi-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-dsb-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-dsb-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-dv-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-dv-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-dz-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-dz-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-el-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-el-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-en-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-en-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-eo-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-eo-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-es-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-es-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-et-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-et-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-eu-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-eu-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-fa-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-fa-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ff-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ff-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-fi-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-fi-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-fil-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-fil-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-fo-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-fo-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-fr-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-fr-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-fur-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-fur-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-fy-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-fy-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ga-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ga-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-gd-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-gd-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-gez-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-gez-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-gl-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-gl-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-gu-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-gu-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-gv-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-gv-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ha-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ha-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-hak-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-hak-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-he-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-he-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-hi-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-hi-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-hif-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-hif-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-hne-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-hne-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-hr-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-hr-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-hsb-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-hsb-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ht-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ht-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-hu-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-hu-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-hy-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-hy-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ia-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ia-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-id-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-id-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ig-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ig-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ik-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ik-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-is-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-is-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-it-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-it-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-iu-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-iu-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ja-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ja-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ka-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ka-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-kab-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-kab-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-kk-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-kk-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-kl-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-kl-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-km-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-km-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-kn-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-kn-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ko-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ko-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-kok-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-kok-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ks-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ks-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ku-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ku-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-kw-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-kw-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ky-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ky-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-lb-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-lb-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-lg-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-lg-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-li-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-li-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-lij-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-lij-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ln-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ln-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-lo-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-lo-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-lt-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-lt-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-lv-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-lv-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-lzh-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-lzh-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mag-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mag-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mai-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mai-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mfe-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mfe-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mg-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mg-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mhr-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mhr-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mi-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mi-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-miq-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-miq-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mjw-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mjw-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mk-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mk-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ml-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ml-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mn-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mn-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mni-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mni-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mr-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mr-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ms-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ms-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-mt-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-mt-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-my-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-my-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-nan-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-nan-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-nb-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-nb-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-nds-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-nds-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ne-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ne-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-nhn-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-nhn-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-niu-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-niu-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-nl-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-nl-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-nn-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-nn-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-nr-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-nr-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-nso-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-nso-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-oc-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-oc-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-om-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-om-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-or-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-or-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-os-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-os-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-pa-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-pa-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-pap-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-pap-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-pl-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-pl-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ps-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ps-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-pt-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-pt-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-quz-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-quz-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-raj-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-raj-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ro-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ro-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ru-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ru-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-rw-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-rw-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sa-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sa-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sah-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sah-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sat-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sat-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sc-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sc-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sd-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sd-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-se-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-se-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sgs-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sgs-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-shn-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-shn-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-shs-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-shs-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-si-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-si-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sid-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sid-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sk-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sk-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sl-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sl-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sm-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sm-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-so-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-so-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sq-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sq-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sr-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sr-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ss-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ss-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-st-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-st-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sv-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sv-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-sw-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-sw-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-szl-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-szl-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ta-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ta-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-tcy-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-tcy-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-te-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-te-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-tg-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-tg-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-th-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-th-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-the-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-the-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ti-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ti-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-tig-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-tig-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-tk-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-tk-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-tl-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-tl-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-tn-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-tn-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-to-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-to-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-tpi-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-tpi-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-tr-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-tr-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ts-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ts-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-tt-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-tt-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ug-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ug-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-uk-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-uk-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-unm-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-unm-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ur-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ur-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-uz-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-uz-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-ve-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-ve-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-vi-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-vi-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-wa-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-wa-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-wae-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-wae-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-wal-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-wal-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-wo-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-wo-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-xh-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-xh-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-yi-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-yi-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-yo-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-yo-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-yue-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-yue-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-yuw-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-yuw-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-zh-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-zh-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-langpack-zu-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-langpack-zu-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-locale-source-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-locale-source-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-minimal-langpack-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-minimal-langpack-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-nss-devel-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-nss-devel-2.28-127.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'glibc-nss-devel-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-static-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-static-2.28-127.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'glibc-static-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'glibc-utils-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'glibc-utils-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'libnsl-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'libnsl-2.28-127.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'libnsl-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'nscd-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'nscd-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'nss_db-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'nss_db-2.28-127.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'nss_db-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'},
    {'reference':'nss_hesiod-2.28-127.0.1.el8', 'cpu':'aarch64', 'release':'8'},
    {'reference':'nss_hesiod-2.28-127.0.1.el8', 'cpu':'i686', 'release':'8'},
    {'reference':'nss_hesiod-2.28-127.0.1.el8', 'cpu':'x86_64', 'release':'8'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'compat-libpthread-nonshared / glibc / glibc-all-langpacks / etc');
}