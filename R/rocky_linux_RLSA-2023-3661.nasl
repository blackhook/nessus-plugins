#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:3661.
##

include('compat.inc');

if (description)
{
  script_id(177603);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/25");

  script_cve_id("CVE-2023-32700");
  script_xref(name:"RLSA", value:"2023:3661");

  script_name(english:"Rocky Linux 8 / 9 : texlive (RLSA-2023:3661)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 / 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2023:3661 advisory.

  - LuaTeX before 1.17.0 allows execution of arbitrary shell commands when compiling a TeX file obtained from
    an untrusted source. This occurs because luatex-core.lua lets the original io.popen be accessed. This also
    affects TeX Live before 2023 r66984 and MiKTeX before 23.5. (CVE-2023-32700)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:3661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2208943");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-adjustbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-algorithms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-alphalph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-amscls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-amsfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-amsmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-anyfontsize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-anysize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-appendix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-arabxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-arphic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-atbegshi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-attachfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-attachfile2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-atveryend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-auxhook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-avantgar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-awesomebox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-babel-english");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-babelbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-beamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-beton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bibtex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bibtex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bibtopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bidi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bigfoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bigintcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bitset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bookman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-bookmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-booktabs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-breakurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-breqn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-capt-of");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-caption");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-carlisle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-catchfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-changebar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-changepage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-charter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-chngcntr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-cite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-cjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-classpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-cm-lgc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-cm-super");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-cmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-cmextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-cns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-collectbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-collection-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-collection-fontsrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-collection-htmlxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-collection-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-collection-latexrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-collection-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-colorprofiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-colortbl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-courier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-crop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-csquotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ctable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ctablestack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-currfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-datetime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-dehyph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-dvipdfmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-dvipng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-dvipng-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-dvips-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-dvisvgm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-dvisvgm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-eepic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-enctex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-enumitem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-environ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-epsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-epstopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-epstopdf-pkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-eqparbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-eso-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-etex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-etex-pkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-etexcmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-etoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-etoolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-euenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-euler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-euro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-eurosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-extsizes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fancybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fancyhdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fancyref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fancyvrb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-filecontents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-filehook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-finstrut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fix2col");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fixlatvian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-float");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fmtcount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fncychap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fontawesome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fontbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fonts-tlwg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fontspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fontware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fontware-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fontwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-footmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-footnotehyper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-fpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-framed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-garuda-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-geometry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-gettitlestring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-glyphlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-gnu-freefont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-graphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-graphics-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-graphics-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-grfext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-grffile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-gsftopk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-gsftopk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-hanging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-helvetic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-hobsub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-hologo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-hycolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-hyperref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-hyph-utf8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-hyphen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-hyphenat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-hyphenex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ifetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ifluatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ifmtarg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ifoddpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ifplatform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-iftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ifxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-index");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-infwarerr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-intcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-jknapltx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-kastrup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-kerkis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-knuth-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-knuth-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-koma-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-kpathsea-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-kvdefinekeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-kvoptions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-kvsetkeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-l3backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-l3experimental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-l3kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-l3packages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lastpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-latex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-latex2man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-latexbug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-latexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-letltxmacro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lettrine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-linegoal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lineno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-listings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-listofitems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lm-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ltabptch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ltxcmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ltxmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lua-alt-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-luahbtex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-luahbtex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lualatex-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lualibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-luaotfload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-luatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-luatex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-luatex85");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-luatexbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-lwarp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-makecmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-makeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-makeindex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-manfnt-font");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-marginnote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-marvosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mathpazo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mathspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mathtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mdwtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-memoir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-metafont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-metafont-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-metalogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-metapost-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mflogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mflogo-font");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mfnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mfware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mfware-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-microtype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-minitoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mnsymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-modes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mparhack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-mptopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-multido");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-multirow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-natbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ncctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ncntrsbk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-needspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-newfloat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-newunicodechar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-norasi-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-notoccite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ntgclass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-oberdiek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-overpic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-palatino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-paralist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-parallel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-parskip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-passivetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pdfcolmk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pdfescape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pdflscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pdfpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pdftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pdftex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pdftexcmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pgf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-philokalia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-placeins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-polyglossia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-powerdot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-preprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-psfrag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pslatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-psnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pspicture");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-arrow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-blur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-coil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-fill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-grad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-plot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-slpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pst-tree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pstricks-add");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ptext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-pxfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-qstest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ragged2e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-rcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-realscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-refcount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-rerunfilecheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-rsfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-sansmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-sansmathaccent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-sauerj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-scheme-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-section");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-sectsty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-seminar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-sepnum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-setspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-showexpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-soul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-stackengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-stmaryrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-stringenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-subfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-subfigure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-svn-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-t2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tabu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tabulary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tex-gyre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tex-gyre-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tex-ini-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tex4ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tex4ht-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-texconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-texlive-common-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-texlive-docindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-texlive-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-texlive-msg-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-texlive-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-texlive-scripts-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-texlive.infra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-textcase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-textpos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-threeparttable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-thumbpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-times");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-titlesec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-titling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tocloft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-translator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-trimspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-txfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-type1cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-typehtml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ucharcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ucharclasses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-uhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-ulem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-underscore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-unicode-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-unicode-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-uniquecounter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-unisugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-updmap-map");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-upquote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-utopia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-varwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-wadalab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-was");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-wasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-wasy-type1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-wasy2-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-wasysym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-wrapfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xcolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xdvi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xecjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xecolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xecyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xepersian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xesearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xetex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xetex-itrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xetex-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xetex-tibetan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xetexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xetexfontinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xifthen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xkeyval");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xltxtra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xmltex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xmltexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xtab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-xunicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-zapfchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-zapfding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:texlive-zref");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^(8|9)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x / 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2023-32700');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RLSA-2023:3661');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'reference':'texlive-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-20180414'},
    {'reference':'texlive-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-20180414'},
    {'reference':'texlive-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-20200406'},
    {'reference':'texlive-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-20200406'},
    {'reference':'texlive-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-20200406'},
    {'reference':'texlive-adjustbox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-adjustbox-20180414'},
    {'reference':'texlive-adjustbox-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-adjustbox-20200406'},
    {'reference':'texlive-ae-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ae-20180414'},
    {'reference':'texlive-ae-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ae-20200406'},
    {'reference':'texlive-algorithms-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-algorithms-20180414'},
    {'reference':'texlive-algorithms-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-algorithms-20200406'},
    {'reference':'texlive-alphalph-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-amscls-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-amscls-20180414'},
    {'reference':'texlive-amscls-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-amscls-20200406'},
    {'reference':'texlive-amsfonts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-amsfonts-20180414'},
    {'reference':'texlive-amsfonts-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-amsfonts-20200406'},
    {'reference':'texlive-amsmath-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-amsmath-20180414'},
    {'reference':'texlive-amsmath-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-amsmath-20200406'},
    {'reference':'texlive-anyfontsize-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-anyfontsize-20180414'},
    {'reference':'texlive-anyfontsize-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-anyfontsize-20200406'},
    {'reference':'texlive-anysize-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-anysize-20180414'},
    {'reference':'texlive-anysize-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-anysize-20200406'},
    {'reference':'texlive-appendix-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-appendix-20180414'},
    {'reference':'texlive-appendix-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-appendix-20200406'},
    {'reference':'texlive-arabxetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-arabxetex-20180414'},
    {'reference':'texlive-arabxetex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-arabxetex-20200406'},
    {'reference':'texlive-arphic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-arphic-20180414'},
    {'reference':'texlive-arphic-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-arphic-20200406'},
    {'reference':'texlive-atbegshi-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-attachfile-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-attachfile-20180414'},
    {'reference':'texlive-attachfile-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-attachfile-20200406'},
    {'reference':'texlive-attachfile2-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-atveryend-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-auxhook-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-avantgar-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-avantgar-20180414'},
    {'reference':'texlive-avantgar-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-avantgar-20200406'},
    {'reference':'texlive-awesomebox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-awesomebox-20180414'},
    {'reference':'texlive-awesomebox-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-awesomebox-20200406'},
    {'reference':'texlive-babel-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-babel-20180414'},
    {'reference':'texlive-babel-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-babel-20200406'},
    {'reference':'texlive-babel-english-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-babel-english-20180414'},
    {'reference':'texlive-babel-english-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-babel-english-20200406'},
    {'reference':'texlive-babelbib-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-babelbib-20180414'},
    {'reference':'texlive-babelbib-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-babelbib-20200406'},
    {'reference':'texlive-base-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-base-20180414'},
    {'reference':'texlive-base-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-base-20200406'},
    {'reference':'texlive-beamer-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-beamer-20180414'},
    {'reference':'texlive-beamer-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-beamer-20200406'},
    {'reference':'texlive-bera-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bera-20180414'},
    {'reference':'texlive-bera-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bera-20200406'},
    {'reference':'texlive-beton-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-beton-20180414'},
    {'reference':'texlive-beton-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-beton-20200406'},
    {'reference':'texlive-bibtex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtex-20180414'},
    {'reference':'texlive-bibtex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtex-20180414'},
    {'reference':'texlive-bibtex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-20200406'},
    {'reference':'texlive-bibtex-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-20200406'},
    {'reference':'texlive-bibtex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-20200406'},
    {'reference':'texlive-bibtex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtex-debuginfo-20180414'},
    {'reference':'texlive-bibtex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtex-debuginfo-20180414'},
    {'reference':'texlive-bibtex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-debuginfo-20200406'},
    {'reference':'texlive-bibtex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-debuginfo-20200406'},
    {'reference':'texlive-bibtex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-debuginfo-20200406'},
    {'reference':'texlive-bibtopic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtopic-20180414'},
    {'reference':'texlive-bibtopic-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtopic-20200406'},
    {'reference':'texlive-bidi-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bidi-20180414'},
    {'reference':'texlive-bidi-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bidi-20200406'},
    {'reference':'texlive-bigfoot-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bigfoot-20180414'},
    {'reference':'texlive-bigfoot-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bigfoot-20200406'},
    {'reference':'texlive-bigintcalc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bitset-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bookman-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bookman-20180414'},
    {'reference':'texlive-bookman-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bookman-20200406'},
    {'reference':'texlive-bookmark-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-booktabs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-booktabs-20180414'},
    {'reference':'texlive-booktabs-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-booktabs-20200406'},
    {'reference':'texlive-breakurl-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-breakurl-20180414'},
    {'reference':'texlive-breakurl-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-breakurl-20200406'},
    {'reference':'texlive-breqn-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-breqn-20180414'},
    {'reference':'texlive-breqn-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-breqn-20200406'},
    {'reference':'texlive-capt-of-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-capt-of-20180414'},
    {'reference':'texlive-capt-of-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-capt-of-20200406'},
    {'reference':'texlive-caption-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-caption-20180414'},
    {'reference':'texlive-caption-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-caption-20200406'},
    {'reference':'texlive-carlisle-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-carlisle-20180414'},
    {'reference':'texlive-carlisle-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-carlisle-20200406'},
    {'reference':'texlive-catchfile-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-changebar-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-changebar-20180414'},
    {'reference':'texlive-changebar-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-changebar-20200406'},
    {'reference':'texlive-changepage-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-changepage-20180414'},
    {'reference':'texlive-changepage-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-changepage-20200406'},
    {'reference':'texlive-charter-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-charter-20180414'},
    {'reference':'texlive-charter-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-charter-20200406'},
    {'reference':'texlive-chngcntr-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-chngcntr-20180414'},
    {'reference':'texlive-chngcntr-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-chngcntr-20200406'},
    {'reference':'texlive-cite-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cite-20180414'},
    {'reference':'texlive-cite-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cite-20200406'},
    {'reference':'texlive-cjk-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cjk-20180414'},
    {'reference':'texlive-cjk-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cjk-20200406'},
    {'reference':'texlive-classpack-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-classpack-20180414'},
    {'reference':'texlive-classpack-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-classpack-20200406'},
    {'reference':'texlive-cm-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cm-20180414'},
    {'reference':'texlive-cm-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cm-20200406'},
    {'reference':'texlive-cm-lgc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cm-lgc-20180414'},
    {'reference':'texlive-cm-lgc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cm-lgc-20200406'},
    {'reference':'texlive-cm-super-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cm-super-20180414'},
    {'reference':'texlive-cm-super-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cm-super-20200406'},
    {'reference':'texlive-cmap-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cmap-20180414'},
    {'reference':'texlive-cmap-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cmap-20200406'},
    {'reference':'texlive-cmextra-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cmextra-20180414'},
    {'reference':'texlive-cmextra-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cmextra-20200406'},
    {'reference':'texlive-cns-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cns-20180414'},
    {'reference':'texlive-cns-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cns-20200406'},
    {'reference':'texlive-collectbox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collectbox-20180414'},
    {'reference':'texlive-collectbox-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collectbox-20200406'},
    {'reference':'texlive-collection-basic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-basic-20180414'},
    {'reference':'texlive-collection-basic-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-basic-20200406'},
    {'reference':'texlive-collection-fontsrecommended-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-fontsrecommended-20180414'},
    {'reference':'texlive-collection-fontsrecommended-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-fontsrecommended-20200406'},
    {'reference':'texlive-collection-htmlxml-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-htmlxml-20180414'},
    {'reference':'texlive-collection-htmlxml-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-htmlxml-20200406'},
    {'reference':'texlive-collection-latex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-latex-20180414'},
    {'reference':'texlive-collection-latex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-latex-20200406'},
    {'reference':'texlive-collection-latexrecommended-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-latexrecommended-20180414'},
    {'reference':'texlive-collection-latexrecommended-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-latexrecommended-20200406'},
    {'reference':'texlive-collection-xetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-xetex-20180414'},
    {'reference':'texlive-collection-xetex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-xetex-20200406'},
    {'reference':'texlive-colorprofiles-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-colortbl-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-colortbl-20180414'},
    {'reference':'texlive-colortbl-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-colortbl-20200406'},
    {'reference':'texlive-context-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-context-20180414'},
    {'reference':'texlive-context-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-context-20200406'},
    {'reference':'texlive-courier-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-courier-20180414'},
    {'reference':'texlive-courier-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-courier-20200406'},
    {'reference':'texlive-crop-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-crop-20180414'},
    {'reference':'texlive-crop-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-crop-20200406'},
    {'reference':'texlive-csquotes-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-csquotes-20180414'},
    {'reference':'texlive-csquotes-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-csquotes-20200406'},
    {'reference':'texlive-ctable-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ctable-20180414'},
    {'reference':'texlive-ctable-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ctable-20200406'},
    {'reference':'texlive-ctablestack-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ctablestack-20180414'},
    {'reference':'texlive-ctablestack-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ctablestack-20200406'},
    {'reference':'texlive-currfile-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-currfile-20180414'},
    {'reference':'texlive-currfile-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-currfile-20200406'},
    {'reference':'texlive-datetime-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-datetime-20180414'},
    {'reference':'texlive-datetime-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-datetime-20200406'},
    {'reference':'texlive-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debuginfo-20180414'},
    {'reference':'texlive-debuginfo-20180414-29.el8_8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debuginfo-20180414'},
    {'reference':'texlive-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debuginfo-20180414'},
    {'reference':'texlive-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debuginfo-20200406'},
    {'reference':'texlive-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debuginfo-20200406'},
    {'reference':'texlive-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debuginfo-20200406'},
    {'reference':'texlive-debugsource-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debugsource-20180414'},
    {'reference':'texlive-debugsource-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debugsource-20180414'},
    {'reference':'texlive-debugsource-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debugsource-20200406'},
    {'reference':'texlive-debugsource-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debugsource-20200406'},
    {'reference':'texlive-debugsource-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debugsource-20200406'},
    {'reference':'texlive-dehyph-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvipdfmx-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipdfmx-20180414'},
    {'reference':'texlive-dvipdfmx-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipdfmx-20180414'},
    {'reference':'texlive-dvipdfmx-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipdfmx-20200406'},
    {'reference':'texlive-dvipdfmx-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipdfmx-20200406'},
    {'reference':'texlive-dvipdfmx-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipdfmx-20200406'},
    {'reference':'texlive-dvipng-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipng-20180414'},
    {'reference':'texlive-dvipng-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipng-20180414'},
    {'reference':'texlive-dvipng-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-20200406'},
    {'reference':'texlive-dvipng-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-20200406'},
    {'reference':'texlive-dvipng-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-20200406'},
    {'reference':'texlive-dvipng-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipng-debuginfo-20180414'},
    {'reference':'texlive-dvipng-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipng-debuginfo-20180414'},
    {'reference':'texlive-dvipng-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-debuginfo-20200406'},
    {'reference':'texlive-dvipng-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-debuginfo-20200406'},
    {'reference':'texlive-dvipng-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-debuginfo-20200406'},
    {'reference':'texlive-dvips-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvips-20180414'},
    {'reference':'texlive-dvips-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvips-20180414'},
    {'reference':'texlive-dvips-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-20200406'},
    {'reference':'texlive-dvips-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-20200406'},
    {'reference':'texlive-dvips-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-20200406'},
    {'reference':'texlive-dvips-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvips-debuginfo-20180414'},
    {'reference':'texlive-dvips-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvips-debuginfo-20180414'},
    {'reference':'texlive-dvips-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-debuginfo-20200406'},
    {'reference':'texlive-dvips-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-debuginfo-20200406'},
    {'reference':'texlive-dvips-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-debuginfo-20200406'},
    {'reference':'texlive-dvisvgm-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvisvgm-20180414'},
    {'reference':'texlive-dvisvgm-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvisvgm-20180414'},
    {'reference':'texlive-dvisvgm-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-20200406'},
    {'reference':'texlive-dvisvgm-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-20200406'},
    {'reference':'texlive-dvisvgm-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-20200406'},
    {'reference':'texlive-dvisvgm-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvisvgm-debuginfo-20180414'},
    {'reference':'texlive-dvisvgm-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvisvgm-debuginfo-20180414'},
    {'reference':'texlive-dvisvgm-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-debuginfo-20200406'},
    {'reference':'texlive-dvisvgm-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-debuginfo-20200406'},
    {'reference':'texlive-dvisvgm-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-debuginfo-20200406'},
    {'reference':'texlive-ec-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ec-20180414'},
    {'reference':'texlive-ec-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ec-20200406'},
    {'reference':'texlive-eepic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-eepic-20180414'},
    {'reference':'texlive-eepic-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-eepic-20200406'},
    {'reference':'texlive-enctex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-enctex-20180414'},
    {'reference':'texlive-enctex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-enctex-20200406'},
    {'reference':'texlive-enumitem-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-enumitem-20180414'},
    {'reference':'texlive-enumitem-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-enumitem-20200406'},
    {'reference':'texlive-environ-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-environ-20180414'},
    {'reference':'texlive-environ-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-environ-20200406'},
    {'reference':'texlive-epsf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-epsf-20180414'},
    {'reference':'texlive-epsf-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-epsf-20200406'},
    {'reference':'texlive-epstopdf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-epstopdf-20180414'},
    {'reference':'texlive-epstopdf-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-epstopdf-20200406'},
    {'reference':'texlive-epstopdf-pkg-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eqparbox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-eqparbox-20180414'},
    {'reference':'texlive-eqparbox-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-eqparbox-20200406'},
    {'reference':'texlive-eso-pic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-eso-pic-20180414'},
    {'reference':'texlive-eso-pic-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-eso-pic-20200406'},
    {'reference':'texlive-etex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-etex-20180414'},
    {'reference':'texlive-etex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-etex-20200406'},
    {'reference':'texlive-etex-pkg-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-etex-pkg-20180414'},
    {'reference':'texlive-etex-pkg-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-etex-pkg-20200406'},
    {'reference':'texlive-etexcmds-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etoc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etoolbox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-etoolbox-20180414'},
    {'reference':'texlive-etoolbox-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-etoolbox-20200406'},
    {'reference':'texlive-euenc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-euenc-20180414'},
    {'reference':'texlive-euenc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-euenc-20200406'},
    {'reference':'texlive-euler-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-euler-20180414'},
    {'reference':'texlive-euler-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-euler-20200406'},
    {'reference':'texlive-euro-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-euro-20180414'},
    {'reference':'texlive-euro-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-euro-20200406'},
    {'reference':'texlive-eurosym-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-eurosym-20180414'},
    {'reference':'texlive-eurosym-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-eurosym-20200406'},
    {'reference':'texlive-extsizes-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-extsizes-20180414'},
    {'reference':'texlive-extsizes-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-extsizes-20200406'},
    {'reference':'texlive-fancybox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fancybox-20180414'},
    {'reference':'texlive-fancybox-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fancybox-20200406'},
    {'reference':'texlive-fancyhdr-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fancyhdr-20180414'},
    {'reference':'texlive-fancyhdr-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fancyhdr-20200406'},
    {'reference':'texlive-fancyref-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fancyref-20180414'},
    {'reference':'texlive-fancyref-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fancyref-20200406'},
    {'reference':'texlive-fancyvrb-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fancyvrb-20180414'},
    {'reference':'texlive-fancyvrb-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fancyvrb-20200406'},
    {'reference':'texlive-filecontents-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-filecontents-20180414'},
    {'reference':'texlive-filecontents-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-filecontents-20200406'},
    {'reference':'texlive-filehook-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-filehook-20180414'},
    {'reference':'texlive-filehook-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-filehook-20200406'},
    {'reference':'texlive-finstrut-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-finstrut-20180414'},
    {'reference':'texlive-finstrut-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-finstrut-20200406'},
    {'reference':'texlive-fix2col-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fix2col-20180414'},
    {'reference':'texlive-fix2col-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fix2col-20200406'},
    {'reference':'texlive-fixlatvian-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fixlatvian-20180414'},
    {'reference':'texlive-fixlatvian-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fixlatvian-20200406'},
    {'reference':'texlive-float-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-float-20180414'},
    {'reference':'texlive-float-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-float-20200406'},
    {'reference':'texlive-fmtcount-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fmtcount-20180414'},
    {'reference':'texlive-fmtcount-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fmtcount-20200406'},
    {'reference':'texlive-fncychap-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fncychap-20180414'},
    {'reference':'texlive-fncychap-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fncychap-20200406'},
    {'reference':'texlive-fontawesome-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontawesome-20180414'},
    {'reference':'texlive-fontawesome-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontawesome-20200406'},
    {'reference':'texlive-fontbook-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontbook-20180414'},
    {'reference':'texlive-fontbook-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontbook-20200406'},
    {'reference':'texlive-fonts-tlwg-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fonts-tlwg-20180414'},
    {'reference':'texlive-fonts-tlwg-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fonts-tlwg-20200406'},
    {'reference':'texlive-fontspec-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontspec-20180414'},
    {'reference':'texlive-fontspec-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontspec-20200406'},
    {'reference':'texlive-fontware-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontware-20180414'},
    {'reference':'texlive-fontware-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontware-20180414'},
    {'reference':'texlive-fontware-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-20200406'},
    {'reference':'texlive-fontware-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-20200406'},
    {'reference':'texlive-fontware-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-20200406'},
    {'reference':'texlive-fontware-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontware-debuginfo-20180414'},
    {'reference':'texlive-fontware-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontware-debuginfo-20180414'},
    {'reference':'texlive-fontware-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-debuginfo-20200406'},
    {'reference':'texlive-fontware-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-debuginfo-20200406'},
    {'reference':'texlive-fontware-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-debuginfo-20200406'},
    {'reference':'texlive-fontwrap-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontwrap-20180414'},
    {'reference':'texlive-fontwrap-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontwrap-20200406'},
    {'reference':'texlive-footmisc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-footmisc-20180414'},
    {'reference':'texlive-footmisc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-footmisc-20200406'},
    {'reference':'texlive-footnotehyper-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fp-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fp-20180414'},
    {'reference':'texlive-fp-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fp-20200406'},
    {'reference':'texlive-fpl-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fpl-20180414'},
    {'reference':'texlive-fpl-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fpl-20200406'},
    {'reference':'texlive-framed-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-framed-20180414'},
    {'reference':'texlive-framed-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-framed-20200406'},
    {'reference':'texlive-garuda-c90-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-garuda-c90-20180414'},
    {'reference':'texlive-garuda-c90-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-garuda-c90-20200406'},
    {'reference':'texlive-geometry-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-geometry-20180414'},
    {'reference':'texlive-geometry-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-geometry-20200406'},
    {'reference':'texlive-gettitlestring-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-glyphlist-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-glyphlist-20180414'},
    {'reference':'texlive-glyphlist-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-glyphlist-20200406'},
    {'reference':'texlive-gnu-freefont-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-graphics-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-graphics-20180414'},
    {'reference':'texlive-graphics-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-graphics-20200406'},
    {'reference':'texlive-graphics-cfg-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-graphics-cfg-20180414'},
    {'reference':'texlive-graphics-cfg-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-graphics-cfg-20200406'},
    {'reference':'texlive-graphics-def-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-graphics-def-20180414'},
    {'reference':'texlive-graphics-def-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-graphics-def-20200406'},
    {'reference':'texlive-grfext-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-grffile-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-gsftopk-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-gsftopk-20180414'},
    {'reference':'texlive-gsftopk-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-gsftopk-20180414'},
    {'reference':'texlive-gsftopk-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-20200406'},
    {'reference':'texlive-gsftopk-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-20200406'},
    {'reference':'texlive-gsftopk-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-20200406'},
    {'reference':'texlive-gsftopk-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-gsftopk-debuginfo-20180414'},
    {'reference':'texlive-gsftopk-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-gsftopk-debuginfo-20180414'},
    {'reference':'texlive-gsftopk-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-debuginfo-20200406'},
    {'reference':'texlive-gsftopk-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-debuginfo-20200406'},
    {'reference':'texlive-gsftopk-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-debuginfo-20200406'},
    {'reference':'texlive-hanging-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-helvetic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-helvetic-20180414'},
    {'reference':'texlive-helvetic-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-helvetic-20200406'},
    {'reference':'texlive-hobsub-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hologo-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hycolor-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyperref-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-hyperref-20180414'},
    {'reference':'texlive-hyperref-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-hyperref-20200406'},
    {'reference':'texlive-hyph-utf8-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-hyph-utf8-20180414'},
    {'reference':'texlive-hyph-utf8-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-hyph-utf8-20200406'},
    {'reference':'texlive-hyphen-base-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-hyphen-base-20180414'},
    {'reference':'texlive-hyphen-base-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-hyphen-base-20200406'},
    {'reference':'texlive-hyphenat-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-hyphenat-20180414'},
    {'reference':'texlive-hyphenat-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-hyphenat-20200406'},
    {'reference':'texlive-hyphenex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ifetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifluatex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifmtarg-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ifmtarg-20180414'},
    {'reference':'texlive-ifmtarg-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ifmtarg-20200406'},
    {'reference':'texlive-ifoddpage-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ifoddpage-20180414'},
    {'reference':'texlive-ifoddpage-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ifoddpage-20200406'},
    {'reference':'texlive-ifplatform-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-iftex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-iftex-20180414'},
    {'reference':'texlive-iftex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-iftex-20200406'},
    {'reference':'texlive-ifxetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-import-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-import-20180414'},
    {'reference':'texlive-import-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-import-20200406'},
    {'reference':'texlive-index-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-index-20180414'},
    {'reference':'texlive-index-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-index-20200406'},
    {'reference':'texlive-infwarerr-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-intcalc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-jadetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-jadetex-20180414'},
    {'reference':'texlive-jadetex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-jadetex-20200406'},
    {'reference':'texlive-jknapltx-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-jknapltx-20180414'},
    {'reference':'texlive-jknapltx-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-jknapltx-20200406'},
    {'reference':'texlive-kastrup-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kastrup-20180414'},
    {'reference':'texlive-kastrup-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kastrup-20200406'},
    {'reference':'texlive-kerkis-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kerkis-20180414'},
    {'reference':'texlive-kerkis-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kerkis-20200406'},
    {'reference':'texlive-knuth-lib-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-knuth-lib-20180414'},
    {'reference':'texlive-knuth-lib-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-knuth-lib-20200406'},
    {'reference':'texlive-knuth-local-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-knuth-local-20180414'},
    {'reference':'texlive-knuth-local-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-knuth-local-20200406'},
    {'reference':'texlive-koma-script-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-koma-script-20180414'},
    {'reference':'texlive-koma-script-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-koma-script-20200406'},
    {'reference':'texlive-kpathsea-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kpathsea-20180414'},
    {'reference':'texlive-kpathsea-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kpathsea-20180414'},
    {'reference':'texlive-kpathsea-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-20200406'},
    {'reference':'texlive-kpathsea-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-20200406'},
    {'reference':'texlive-kpathsea-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-20200406'},
    {'reference':'texlive-kpathsea-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kpathsea-debuginfo-20180414'},
    {'reference':'texlive-kpathsea-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kpathsea-debuginfo-20180414'},
    {'reference':'texlive-kpathsea-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-debuginfo-20200406'},
    {'reference':'texlive-kpathsea-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-debuginfo-20200406'},
    {'reference':'texlive-kpathsea-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-debuginfo-20200406'},
    {'reference':'texlive-kvdefinekeys-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvoptions-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvsetkeys-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3backend-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3experimental-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-l3experimental-20180414'},
    {'reference':'texlive-l3experimental-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-l3experimental-20200406'},
    {'reference':'texlive-l3kernel-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-l3kernel-20180414'},
    {'reference':'texlive-l3kernel-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-l3kernel-20200406'},
    {'reference':'texlive-l3packages-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-l3packages-20180414'},
    {'reference':'texlive-l3packages-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-l3packages-20200406'},
    {'reference':'texlive-lastpage-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lastpage-20180414'},
    {'reference':'texlive-lastpage-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lastpage-20200406'},
    {'reference':'texlive-latex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-latex-20180414'},
    {'reference':'texlive-latex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-latex-20200406'},
    {'reference':'texlive-latex-fonts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-latex-fonts-20180414'},
    {'reference':'texlive-latex-fonts-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-latex-fonts-20200406'},
    {'reference':'texlive-latex2man-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-latex2man-20180414'},
    {'reference':'texlive-latex2man-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-latex2man-20200406'},
    {'reference':'texlive-latexbug-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latexconfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-latexconfig-20180414'},
    {'reference':'texlive-latexconfig-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-latexconfig-20200406'},
    {'reference':'texlive-letltxmacro-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lettrine-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lettrine-20180414'},
    {'reference':'texlive-lettrine-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lettrine-20200406'},
    {'reference':'texlive-lib-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-20180414'},
    {'reference':'texlive-lib-20180414-29.el8_8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-20180414'},
    {'reference':'texlive-lib-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-20180414'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-20200406'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-20200406'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-20200406'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-20200406'},
    {'reference':'texlive-lib-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-debuginfo-20180414'},
    {'reference':'texlive-lib-debuginfo-20180414-29.el8_8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-debuginfo-20180414'},
    {'reference':'texlive-lib-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-debuginfo-20180414'},
    {'reference':'texlive-lib-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-debuginfo-20200406'},
    {'reference':'texlive-lib-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-debuginfo-20200406'},
    {'reference':'texlive-lib-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-debuginfo-20200406'},
    {'reference':'texlive-lib-devel-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-devel-20180414'},
    {'reference':'texlive-lib-devel-20180414-29.el8_8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-devel-20180414'},
    {'reference':'texlive-lib-devel-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-devel-20180414'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-devel-20200406'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-devel-20200406'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-devel-20200406'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-devel-20200406'},
    {'reference':'texlive-linegoal-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-linegoal-20180414'},
    {'reference':'texlive-linegoal-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-linegoal-20200406'},
    {'reference':'texlive-lineno-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lineno-20180414'},
    {'reference':'texlive-lineno-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lineno-20200406'},
    {'reference':'texlive-listings-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-listings-20180414'},
    {'reference':'texlive-listings-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-listings-20200406'},
    {'reference':'texlive-listofitems-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lm-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lm-20180414'},
    {'reference':'texlive-lm-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lm-20200406'},
    {'reference':'texlive-lm-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lm-math-20180414'},
    {'reference':'texlive-lm-math-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lm-math-20200406'},
    {'reference':'texlive-ltabptch-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ltabptch-20180414'},
    {'reference':'texlive-ltabptch-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ltabptch-20200406'},
    {'reference':'texlive-ltxcmds-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ltxmisc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ltxmisc-20180414'},
    {'reference':'texlive-ltxmisc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ltxmisc-20200406'},
    {'reference':'texlive-lua-alt-getopt-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lua-alt-getopt-20180414'},
    {'reference':'texlive-lua-alt-getopt-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lua-alt-getopt-20200406'},
    {'reference':'texlive-luahbtex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lualatex-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lualatex-math-20180414'},
    {'reference':'texlive-lualatex-math-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lualatex-math-20200406'},
    {'reference':'texlive-lualibs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lualibs-20180414'},
    {'reference':'texlive-lualibs-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lualibs-20200406'},
    {'reference':'texlive-luaotfload-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luaotfload-20180414'},
    {'reference':'texlive-luaotfload-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luaotfload-20200406'},
    {'reference':'texlive-luatex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex-20180414'},
    {'reference':'texlive-luatex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex-20180414'},
    {'reference':'texlive-luatex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-20200406'},
    {'reference':'texlive-luatex-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-20200406'},
    {'reference':'texlive-luatex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-20200406'},
    {'reference':'texlive-luatex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex-debuginfo-20180414'},
    {'reference':'texlive-luatex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex-debuginfo-20180414'},
    {'reference':'texlive-luatex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-debuginfo-20200406'},
    {'reference':'texlive-luatex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-debuginfo-20200406'},
    {'reference':'texlive-luatex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-debuginfo-20200406'},
    {'reference':'texlive-luatex85-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex85-20180414'},
    {'reference':'texlive-luatex85-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex85-20200406'},
    {'reference':'texlive-luatexbase-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatexbase-20180414'},
    {'reference':'texlive-luatexbase-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatexbase-20200406'},
    {'reference':'texlive-lwarp-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-makecmds-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makecmds-20180414'},
    {'reference':'texlive-makecmds-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makecmds-20200406'},
    {'reference':'texlive-makeindex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makeindex-20180414'},
    {'reference':'texlive-makeindex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makeindex-20180414'},
    {'reference':'texlive-makeindex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-20200406'},
    {'reference':'texlive-makeindex-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-20200406'},
    {'reference':'texlive-makeindex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-20200406'},
    {'reference':'texlive-makeindex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makeindex-debuginfo-20180414'},
    {'reference':'texlive-makeindex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makeindex-debuginfo-20180414'},
    {'reference':'texlive-makeindex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-debuginfo-20200406'},
    {'reference':'texlive-makeindex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-debuginfo-20200406'},
    {'reference':'texlive-makeindex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-debuginfo-20200406'},
    {'reference':'texlive-manfnt-font-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-manfnt-font-20180414'},
    {'reference':'texlive-manfnt-font-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-manfnt-font-20200406'},
    {'reference':'texlive-marginnote-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-marginnote-20180414'},
    {'reference':'texlive-marginnote-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-marginnote-20200406'},
    {'reference':'texlive-marvosym-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-marvosym-20180414'},
    {'reference':'texlive-marvosym-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-marvosym-20200406'},
    {'reference':'texlive-mathpazo-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mathpazo-20180414'},
    {'reference':'texlive-mathpazo-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mathpazo-20200406'},
    {'reference':'texlive-mathspec-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mathspec-20180414'},
    {'reference':'texlive-mathspec-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mathspec-20200406'},
    {'reference':'texlive-mathtools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mathtools-20180414'},
    {'reference':'texlive-mathtools-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mathtools-20200406'},
    {'reference':'texlive-mdwtools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mdwtools-20180414'},
    {'reference':'texlive-mdwtools-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mdwtools-20200406'},
    {'reference':'texlive-memoir-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-memoir-20180414'},
    {'reference':'texlive-memoir-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-memoir-20200406'},
    {'reference':'texlive-metafont-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metafont-20180414'},
    {'reference':'texlive-metafont-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metafont-20180414'},
    {'reference':'texlive-metafont-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-20200406'},
    {'reference':'texlive-metafont-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-20200406'},
    {'reference':'texlive-metafont-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-20200406'},
    {'reference':'texlive-metafont-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metafont-debuginfo-20180414'},
    {'reference':'texlive-metafont-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metafont-debuginfo-20180414'},
    {'reference':'texlive-metafont-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-debuginfo-20200406'},
    {'reference':'texlive-metafont-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-debuginfo-20200406'},
    {'reference':'texlive-metafont-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-debuginfo-20200406'},
    {'reference':'texlive-metalogo-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metalogo-20180414'},
    {'reference':'texlive-metalogo-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metalogo-20200406'},
    {'reference':'texlive-metapost-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metapost-20180414'},
    {'reference':'texlive-metapost-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metapost-20180414'},
    {'reference':'texlive-metapost-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-20200406'},
    {'reference':'texlive-metapost-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-20200406'},
    {'reference':'texlive-metapost-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-20200406'},
    {'reference':'texlive-metapost-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metapost-debuginfo-20180414'},
    {'reference':'texlive-metapost-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metapost-debuginfo-20180414'},
    {'reference':'texlive-metapost-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-debuginfo-20200406'},
    {'reference':'texlive-metapost-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-debuginfo-20200406'},
    {'reference':'texlive-metapost-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-debuginfo-20200406'},
    {'reference':'texlive-mflogo-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mflogo-20180414'},
    {'reference':'texlive-mflogo-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mflogo-20200406'},
    {'reference':'texlive-mflogo-font-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mflogo-font-20180414'},
    {'reference':'texlive-mflogo-font-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mflogo-font-20200406'},
    {'reference':'texlive-mfnfss-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfnfss-20180414'},
    {'reference':'texlive-mfnfss-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfnfss-20200406'},
    {'reference':'texlive-mfware-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfware-20180414'},
    {'reference':'texlive-mfware-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfware-20180414'},
    {'reference':'texlive-mfware-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-20200406'},
    {'reference':'texlive-mfware-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-20200406'},
    {'reference':'texlive-mfware-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-20200406'},
    {'reference':'texlive-mfware-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfware-debuginfo-20180414'},
    {'reference':'texlive-mfware-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfware-debuginfo-20180414'},
    {'reference':'texlive-mfware-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-debuginfo-20200406'},
    {'reference':'texlive-mfware-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-debuginfo-20200406'},
    {'reference':'texlive-mfware-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-debuginfo-20200406'},
    {'reference':'texlive-microtype-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-microtype-20180414'},
    {'reference':'texlive-microtype-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-microtype-20200406'},
    {'reference':'texlive-minitoc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mnsymbol-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mnsymbol-20180414'},
    {'reference':'texlive-mnsymbol-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mnsymbol-20200406'},
    {'reference':'texlive-modes-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mparhack-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mparhack-20180414'},
    {'reference':'texlive-mparhack-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mparhack-20200406'},
    {'reference':'texlive-mptopdf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mptopdf-20180414'},
    {'reference':'texlive-mptopdf-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mptopdf-20200406'},
    {'reference':'texlive-ms-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ms-20180414'},
    {'reference':'texlive-ms-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ms-20200406'},
    {'reference':'texlive-multido-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-multido-20180414'},
    {'reference':'texlive-multido-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-multido-20200406'},
    {'reference':'texlive-multirow-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-multirow-20180414'},
    {'reference':'texlive-multirow-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-multirow-20200406'},
    {'reference':'texlive-natbib-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-natbib-20180414'},
    {'reference':'texlive-natbib-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-natbib-20200406'},
    {'reference':'texlive-ncctools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ncctools-20180414'},
    {'reference':'texlive-ncctools-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ncctools-20200406'},
    {'reference':'texlive-ncntrsbk-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ncntrsbk-20180414'},
    {'reference':'texlive-ncntrsbk-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ncntrsbk-20200406'},
    {'reference':'texlive-needspace-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-needspace-20180414'},
    {'reference':'texlive-needspace-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-needspace-20200406'},
    {'reference':'texlive-newfloat-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-newunicodechar-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-norasi-c90-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-norasi-c90-20180414'},
    {'reference':'texlive-norasi-c90-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-norasi-c90-20200406'},
    {'reference':'texlive-notoccite-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ntgclass-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ntgclass-20180414'},
    {'reference':'texlive-ntgclass-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ntgclass-20200406'},
    {'reference':'texlive-oberdiek-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-oberdiek-20180414'},
    {'reference':'texlive-oberdiek-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-oberdiek-20200406'},
    {'reference':'texlive-obsolete-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-overpic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-overpic-20180414'},
    {'reference':'texlive-overpic-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-overpic-20200406'},
    {'reference':'texlive-palatino-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-palatino-20180414'},
    {'reference':'texlive-palatino-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-palatino-20200406'},
    {'reference':'texlive-paralist-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-paralist-20180414'},
    {'reference':'texlive-paralist-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-paralist-20200406'},
    {'reference':'texlive-parallel-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-parallel-20180414'},
    {'reference':'texlive-parallel-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-parallel-20200406'},
    {'reference':'texlive-parskip-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-parskip-20180414'},
    {'reference':'texlive-parskip-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-parskip-20200406'},
    {'reference':'texlive-passivetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-passivetex-20180414'},
    {'reference':'texlive-passivetex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-passivetex-20200406'},
    {'reference':'texlive-pdfcolmk-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfescape-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdflscape-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfpages-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdfpages-20180414'},
    {'reference':'texlive-pdfpages-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdfpages-20200406'},
    {'reference':'texlive-pdftex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdftex-20180414'},
    {'reference':'texlive-pdftex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdftex-20180414'},
    {'reference':'texlive-pdftex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-20200406'},
    {'reference':'texlive-pdftex-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-20200406'},
    {'reference':'texlive-pdftex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-20200406'},
    {'reference':'texlive-pdftex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdftex-debuginfo-20180414'},
    {'reference':'texlive-pdftex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdftex-debuginfo-20180414'},
    {'reference':'texlive-pdftex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-debuginfo-20200406'},
    {'reference':'texlive-pdftex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-debuginfo-20200406'},
    {'reference':'texlive-pdftex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-debuginfo-20200406'},
    {'reference':'texlive-pdftexcmds-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pgf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pgf-20180414'},
    {'reference':'texlive-pgf-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pgf-20200406'},
    {'reference':'texlive-philokalia-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-philokalia-20180414'},
    {'reference':'texlive-philokalia-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-philokalia-20200406'},
    {'reference':'texlive-placeins-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-placeins-20180414'},
    {'reference':'texlive-placeins-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-placeins-20200406'},
    {'reference':'texlive-plain-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-plain-20180414'},
    {'reference':'texlive-plain-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-plain-20200406'},
    {'reference':'texlive-polyglossia-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-polyglossia-20180414'},
    {'reference':'texlive-polyglossia-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-polyglossia-20200406'},
    {'reference':'texlive-powerdot-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-powerdot-20180414'},
    {'reference':'texlive-powerdot-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-powerdot-20200406'},
    {'reference':'texlive-preprint-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-preprint-20180414'},
    {'reference':'texlive-preprint-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-preprint-20200406'},
    {'reference':'texlive-psfrag-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-psfrag-20180414'},
    {'reference':'texlive-psfrag-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-psfrag-20200406'},
    {'reference':'texlive-pslatex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pslatex-20180414'},
    {'reference':'texlive-pslatex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pslatex-20200406'},
    {'reference':'texlive-psnfss-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-psnfss-20180414'},
    {'reference':'texlive-psnfss-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-psnfss-20200406'},
    {'reference':'texlive-pspicture-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pspicture-20180414'},
    {'reference':'texlive-pspicture-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pspicture-20200406'},
    {'reference':'texlive-pst-3d-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-3d-20180414'},
    {'reference':'texlive-pst-3d-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-3d-20200406'},
    {'reference':'texlive-pst-arrow-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-arrow-20180414'},
    {'reference':'texlive-pst-arrow-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-arrow-20200406'},
    {'reference':'texlive-pst-blur-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-blur-20180414'},
    {'reference':'texlive-pst-blur-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-blur-20200406'},
    {'reference':'texlive-pst-coil-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-coil-20180414'},
    {'reference':'texlive-pst-coil-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-coil-20200406'},
    {'reference':'texlive-pst-eps-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-eps-20180414'},
    {'reference':'texlive-pst-eps-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-eps-20200406'},
    {'reference':'texlive-pst-fill-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-fill-20180414'},
    {'reference':'texlive-pst-fill-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-fill-20200406'},
    {'reference':'texlive-pst-grad-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-grad-20180414'},
    {'reference':'texlive-pst-grad-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-grad-20200406'},
    {'reference':'texlive-pst-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-math-20180414'},
    {'reference':'texlive-pst-math-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-math-20200406'},
    {'reference':'texlive-pst-node-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-node-20180414'},
    {'reference':'texlive-pst-node-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-node-20200406'},
    {'reference':'texlive-pst-plot-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-plot-20180414'},
    {'reference':'texlive-pst-plot-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-plot-20200406'},
    {'reference':'texlive-pst-slpe-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-slpe-20180414'},
    {'reference':'texlive-pst-slpe-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-slpe-20200406'},
    {'reference':'texlive-pst-text-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-text-20180414'},
    {'reference':'texlive-pst-text-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-text-20200406'},
    {'reference':'texlive-pst-tools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-tools-20180414'},
    {'reference':'texlive-pst-tools-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-tools-20200406'},
    {'reference':'texlive-pst-tree-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-tree-20180414'},
    {'reference':'texlive-pst-tree-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-tree-20200406'},
    {'reference':'texlive-pstricks-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pstricks-20180414'},
    {'reference':'texlive-pstricks-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pstricks-20200406'},
    {'reference':'texlive-pstricks-add-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pstricks-add-20180414'},
    {'reference':'texlive-pstricks-add-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pstricks-add-20200406'},
    {'reference':'texlive-ptext-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ptext-20180414'},
    {'reference':'texlive-ptext-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ptext-20200406'},
    {'reference':'texlive-pxfonts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pxfonts-20180414'},
    {'reference':'texlive-pxfonts-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pxfonts-20200406'},
    {'reference':'texlive-qstest-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-qstest-20180414'},
    {'reference':'texlive-qstest-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-qstest-20200406'},
    {'reference':'texlive-ragged2e-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rcs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-rcs-20180414'},
    {'reference':'texlive-rcs-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-rcs-20200406'},
    {'reference':'texlive-realscripts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-realscripts-20180414'},
    {'reference':'texlive-realscripts-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-realscripts-20200406'},
    {'reference':'texlive-refcount-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rerunfilecheck-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rsfs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-rsfs-20180414'},
    {'reference':'texlive-rsfs-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-rsfs-20200406'},
    {'reference':'texlive-sansmath-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-sansmath-20180414'},
    {'reference':'texlive-sansmath-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-sansmath-20200406'},
    {'reference':'texlive-sansmathaccent-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sauerj-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-sauerj-20180414'},
    {'reference':'texlive-sauerj-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-sauerj-20200406'},
    {'reference':'texlive-scheme-basic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-scheme-basic-20180414'},
    {'reference':'texlive-scheme-basic-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-scheme-basic-20200406'},
    {'reference':'texlive-section-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-section-20180414'},
    {'reference':'texlive-section-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-section-20200406'},
    {'reference':'texlive-sectsty-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-sectsty-20180414'},
    {'reference':'texlive-sectsty-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-sectsty-20200406'},
    {'reference':'texlive-seminar-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-seminar-20180414'},
    {'reference':'texlive-seminar-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-seminar-20200406'},
    {'reference':'texlive-sepnum-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-sepnum-20180414'},
    {'reference':'texlive-sepnum-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-sepnum-20200406'},
    {'reference':'texlive-setspace-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-setspace-20180414'},
    {'reference':'texlive-setspace-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-setspace-20200406'},
    {'reference':'texlive-showexpl-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-showexpl-20180414'},
    {'reference':'texlive-showexpl-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-showexpl-20200406'},
    {'reference':'texlive-soul-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-soul-20180414'},
    {'reference':'texlive-soul-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-soul-20200406'},
    {'reference':'texlive-stackengine-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-stmaryrd-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-stmaryrd-20180414'},
    {'reference':'texlive-stmaryrd-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-stmaryrd-20200406'},
    {'reference':'texlive-stringenc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-subfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-subfig-20180414'},
    {'reference':'texlive-subfig-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-subfig-20200406'},
    {'reference':'texlive-subfigure-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-subfigure-20180414'},
    {'reference':'texlive-subfigure-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-subfigure-20200406'},
    {'reference':'texlive-svn-prov-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-svn-prov-20180414'},
    {'reference':'texlive-svn-prov-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-svn-prov-20200406'},
    {'reference':'texlive-symbol-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-symbol-20180414'},
    {'reference':'texlive-symbol-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-symbol-20200406'},
    {'reference':'texlive-t2-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-t2-20180414'},
    {'reference':'texlive-t2-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-t2-20200406'},
    {'reference':'texlive-tabu-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tabu-20180414'},
    {'reference':'texlive-tabu-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tabu-20200406'},
    {'reference':'texlive-tabulary-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tabulary-20180414'},
    {'reference':'texlive-tabulary-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tabulary-20200406'},
    {'reference':'texlive-tetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-20180414'},
    {'reference':'texlive-tex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-20180414'},
    {'reference':'texlive-tex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-20200406'},
    {'reference':'texlive-tex-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-20200406'},
    {'reference':'texlive-tex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-20200406'},
    {'reference':'texlive-tex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-debuginfo-20180414'},
    {'reference':'texlive-tex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-debuginfo-20180414'},
    {'reference':'texlive-tex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-debuginfo-20200406'},
    {'reference':'texlive-tex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-debuginfo-20200406'},
    {'reference':'texlive-tex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-debuginfo-20200406'},
    {'reference':'texlive-tex-gyre-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-gyre-20180414'},
    {'reference':'texlive-tex-gyre-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-gyre-20200406'},
    {'reference':'texlive-tex-gyre-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-gyre-math-20180414'},
    {'reference':'texlive-tex-gyre-math-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-gyre-math-20200406'},
    {'reference':'texlive-tex-ini-files-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-ini-files-20180414'},
    {'reference':'texlive-tex-ini-files-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-ini-files-20200406'},
    {'reference':'texlive-tex4ht-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex4ht-20180414'},
    {'reference':'texlive-tex4ht-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex4ht-20180414'},
    {'reference':'texlive-tex4ht-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-20200406'},
    {'reference':'texlive-tex4ht-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-20200406'},
    {'reference':'texlive-tex4ht-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-20200406'},
    {'reference':'texlive-tex4ht-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex4ht-debuginfo-20180414'},
    {'reference':'texlive-tex4ht-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex4ht-debuginfo-20180414'},
    {'reference':'texlive-tex4ht-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-debuginfo-20200406'},
    {'reference':'texlive-tex4ht-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-debuginfo-20200406'},
    {'reference':'texlive-tex4ht-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-debuginfo-20200406'},
    {'reference':'texlive-texconfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-common-doc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-common-doc-20180414'},
    {'reference':'texlive-texlive-common-doc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-common-doc-20200406'},
    {'reference':'texlive-texlive-docindex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-docindex-20180414'},
    {'reference':'texlive-texlive-docindex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-docindex-20200406'},
    {'reference':'texlive-texlive-en-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-en-20180414'},
    {'reference':'texlive-texlive-en-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-en-20200406'},
    {'reference':'texlive-texlive-msg-translations-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-msg-translations-20180414'},
    {'reference':'texlive-texlive-msg-translations-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-msg-translations-20200406'},
    {'reference':'texlive-texlive-scripts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-scripts-20180414'},
    {'reference':'texlive-texlive-scripts-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-scripts-20200406'},
    {'reference':'texlive-texlive-scripts-extra-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive.infra-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive.infra-20180414'},
    {'reference':'texlive-texlive.infra-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive.infra-20200406'},
    {'reference':'texlive-textcase-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-textcase-20180414'},
    {'reference':'texlive-textcase-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-textcase-20200406'},
    {'reference':'texlive-textpos-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-textpos-20180414'},
    {'reference':'texlive-textpos-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-textpos-20200406'},
    {'reference':'texlive-threeparttable-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-threeparttable-20180414'},
    {'reference':'texlive-threeparttable-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-threeparttable-20200406'},
    {'reference':'texlive-thumbpdf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-thumbpdf-20180414'},
    {'reference':'texlive-thumbpdf-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-thumbpdf-20200406'},
    {'reference':'texlive-times-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-times-20180414'},
    {'reference':'texlive-times-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-times-20200406'},
    {'reference':'texlive-tipa-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tipa-20180414'},
    {'reference':'texlive-tipa-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tipa-20200406'},
    {'reference':'texlive-titlesec-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-titlesec-20180414'},
    {'reference':'texlive-titlesec-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-titlesec-20200406'},
    {'reference':'texlive-titling-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-titling-20180414'},
    {'reference':'texlive-titling-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-titling-20200406'},
    {'reference':'texlive-tocloft-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tocloft-20180414'},
    {'reference':'texlive-tocloft-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tocloft-20200406'},
    {'reference':'texlive-tools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tools-20180414'},
    {'reference':'texlive-tools-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tools-20200406'},
    {'reference':'texlive-translator-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-translator-20180414'},
    {'reference':'texlive-translator-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-translator-20200406'},
    {'reference':'texlive-trimspaces-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-trimspaces-20180414'},
    {'reference':'texlive-trimspaces-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-trimspaces-20200406'},
    {'reference':'texlive-txfonts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-txfonts-20180414'},
    {'reference':'texlive-txfonts-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-txfonts-20200406'},
    {'reference':'texlive-type1cm-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-type1cm-20180414'},
    {'reference':'texlive-type1cm-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-type1cm-20200406'},
    {'reference':'texlive-typehtml-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-typehtml-20180414'},
    {'reference':'texlive-typehtml-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-typehtml-20200406'},
    {'reference':'texlive-ucharcat-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ucharclasses-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ucharclasses-20180414'},
    {'reference':'texlive-ucharclasses-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ucharclasses-20200406'},
    {'reference':'texlive-ucs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ucs-20180414'},
    {'reference':'texlive-ucs-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ucs-20200406'},
    {'reference':'texlive-uhc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-uhc-20180414'},
    {'reference':'texlive-uhc-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-uhc-20200406'},
    {'reference':'texlive-ulem-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ulem-20180414'},
    {'reference':'texlive-ulem-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ulem-20200406'},
    {'reference':'texlive-underscore-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-underscore-20180414'},
    {'reference':'texlive-underscore-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-underscore-20200406'},
    {'reference':'texlive-unicode-data-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-unicode-data-20180414'},
    {'reference':'texlive-unicode-data-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-unicode-data-20200406'},
    {'reference':'texlive-unicode-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-unicode-math-20180414'},
    {'reference':'texlive-unicode-math-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-unicode-math-20200406'},
    {'reference':'texlive-uniquecounter-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-unisugar-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-unisugar-20180414'},
    {'reference':'texlive-unisugar-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-unisugar-20200406'},
    {'reference':'texlive-updmap-map-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-updmap-map-20180414'},
    {'reference':'texlive-updmap-map-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-updmap-map-20200406'},
    {'reference':'texlive-upquote-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-upquote-20180414'},
    {'reference':'texlive-upquote-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-upquote-20200406'},
    {'reference':'texlive-url-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-url-20180414'},
    {'reference':'texlive-url-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-url-20200406'},
    {'reference':'texlive-utopia-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-utopia-20180414'},
    {'reference':'texlive-utopia-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-utopia-20200406'},
    {'reference':'texlive-varwidth-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-varwidth-20180414'},
    {'reference':'texlive-varwidth-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-varwidth-20200406'},
    {'reference':'texlive-wadalab-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-wadalab-20180414'},
    {'reference':'texlive-wadalab-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-wadalab-20200406'},
    {'reference':'texlive-was-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-was-20180414'},
    {'reference':'texlive-was-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-was-20200406'},
    {'reference':'texlive-wasy-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-wasy-20180414'},
    {'reference':'texlive-wasy-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-wasy-20200406'},
    {'reference':'texlive-wasy-type1-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wasy2-ps-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasysym-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-wasysym-20180414'},
    {'reference':'texlive-wasysym-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-wasysym-20200406'},
    {'reference':'texlive-wrapfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-wrapfig-20180414'},
    {'reference':'texlive-wrapfig-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-wrapfig-20200406'},
    {'reference':'texlive-xcolor-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xcolor-20180414'},
    {'reference':'texlive-xcolor-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xcolor-20200406'},
    {'reference':'texlive-xdvi-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xdvi-20180414'},
    {'reference':'texlive-xdvi-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xdvi-20180414'},
    {'reference':'texlive-xdvi-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-20200406'},
    {'reference':'texlive-xdvi-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-20200406'},
    {'reference':'texlive-xdvi-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-20200406'},
    {'reference':'texlive-xdvi-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xdvi-debuginfo-20180414'},
    {'reference':'texlive-xdvi-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xdvi-debuginfo-20180414'},
    {'reference':'texlive-xdvi-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-debuginfo-20200406'},
    {'reference':'texlive-xdvi-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-debuginfo-20200406'},
    {'reference':'texlive-xdvi-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-debuginfo-20200406'},
    {'reference':'texlive-xecjk-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xecjk-20180414'},
    {'reference':'texlive-xecjk-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xecjk-20200406'},
    {'reference':'texlive-xecolor-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xecolor-20180414'},
    {'reference':'texlive-xecolor-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xecolor-20200406'},
    {'reference':'texlive-xecyr-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xecyr-20180414'},
    {'reference':'texlive-xecyr-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xecyr-20200406'},
    {'reference':'texlive-xeindex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xeindex-20180414'},
    {'reference':'texlive-xeindex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xeindex-20200406'},
    {'reference':'texlive-xepersian-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xepersian-20180414'},
    {'reference':'texlive-xepersian-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xepersian-20200406'},
    {'reference':'texlive-xesearch-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xesearch-20180414'},
    {'reference':'texlive-xesearch-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xesearch-20200406'},
    {'reference':'texlive-xetex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-20180414'},
    {'reference':'texlive-xetex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-20180414'},
    {'reference':'texlive-xetex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-20200406'},
    {'reference':'texlive-xetex-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-20200406'},
    {'reference':'texlive-xetex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-20200406'},
    {'reference':'texlive-xetex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-debuginfo-20180414'},
    {'reference':'texlive-xetex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-debuginfo-20180414'},
    {'reference':'texlive-xetex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-debuginfo-20200406'},
    {'reference':'texlive-xetex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-debuginfo-20200406'},
    {'reference':'texlive-xetex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-debuginfo-20200406'},
    {'reference':'texlive-xetex-itrans-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-itrans-20180414'},
    {'reference':'texlive-xetex-itrans-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-itrans-20200406'},
    {'reference':'texlive-xetex-pstricks-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-pstricks-20180414'},
    {'reference':'texlive-xetex-pstricks-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-pstricks-20200406'},
    {'reference':'texlive-xetex-tibetan-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-tibetan-20180414'},
    {'reference':'texlive-xetex-tibetan-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-tibetan-20200406'},
    {'reference':'texlive-xetexconfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetexconfig-20180414'},
    {'reference':'texlive-xetexconfig-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetexconfig-20200406'},
    {'reference':'texlive-xetexfontinfo-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetexfontinfo-20180414'},
    {'reference':'texlive-xetexfontinfo-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetexfontinfo-20200406'},
    {'reference':'texlive-xifthen-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xifthen-20180414'},
    {'reference':'texlive-xifthen-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xifthen-20200406'},
    {'reference':'texlive-xkeyval-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xkeyval-20180414'},
    {'reference':'texlive-xkeyval-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xkeyval-20200406'},
    {'reference':'texlive-xltxtra-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xltxtra-20180414'},
    {'reference':'texlive-xltxtra-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xltxtra-20200406'},
    {'reference':'texlive-xmltex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xmltex-20180414'},
    {'reference':'texlive-xmltex-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xmltex-20200406'},
    {'reference':'texlive-xmltexconfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xmltexconfig-20180414'},
    {'reference':'texlive-xmltexconfig-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xmltexconfig-20200406'},
    {'reference':'texlive-xstring-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xstring-20180414'},
    {'reference':'texlive-xstring-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xstring-20200406'},
    {'reference':'texlive-xtab-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xtab-20180414'},
    {'reference':'texlive-xtab-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xtab-20200406'},
    {'reference':'texlive-xunicode-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xunicode-20180414'},
    {'reference':'texlive-xunicode-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xunicode-20200406'},
    {'reference':'texlive-zapfchan-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-zapfchan-20180414'},
    {'reference':'texlive-zapfchan-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-zapfchan-20200406'},
    {'reference':'texlive-zapfding-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-zapfding-20180414'},
    {'reference':'texlive-zapfding-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-zapfding-20200406'},
    {'reference':'texlive-zref-20200406-26.el9_2', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-20180414'},
    {'reference':'texlive-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-20180414'},
    {'reference':'texlive-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-20200406'},
    {'reference':'texlive-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-20200406'},
    {'reference':'texlive-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-20200406'},
    {'reference':'texlive-adjustbox-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-adjustbox-20180414'},
    {'reference':'texlive-adjustbox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-adjustbox-20200406'},
    {'reference':'texlive-ae-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ae-20180414'},
    {'reference':'texlive-ae-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ae-20200406'},
    {'reference':'texlive-algorithms-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-algorithms-20180414'},
    {'reference':'texlive-algorithms-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-algorithms-20200406'},
    {'reference':'texlive-alphalph-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-amscls-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-amscls-20180414'},
    {'reference':'texlive-amscls-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-amscls-20200406'},
    {'reference':'texlive-amsfonts-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-amsfonts-20180414'},
    {'reference':'texlive-amsfonts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-amsfonts-20200406'},
    {'reference':'texlive-amsmath-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-amsmath-20180414'},
    {'reference':'texlive-amsmath-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-amsmath-20200406'},
    {'reference':'texlive-anyfontsize-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-anyfontsize-20180414'},
    {'reference':'texlive-anyfontsize-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-anyfontsize-20200406'},
    {'reference':'texlive-anysize-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-anysize-20180414'},
    {'reference':'texlive-anysize-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-anysize-20200406'},
    {'reference':'texlive-appendix-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-appendix-20180414'},
    {'reference':'texlive-appendix-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-appendix-20200406'},
    {'reference':'texlive-arabxetex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-arabxetex-20180414'},
    {'reference':'texlive-arabxetex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-arabxetex-20200406'},
    {'reference':'texlive-arphic-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-arphic-20180414'},
    {'reference':'texlive-arphic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-arphic-20200406'},
    {'reference':'texlive-atbegshi-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-attachfile-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-attachfile-20180414'},
    {'reference':'texlive-attachfile-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-attachfile-20200406'},
    {'reference':'texlive-attachfile2-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-atveryend-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-auxhook-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-avantgar-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-avantgar-20180414'},
    {'reference':'texlive-avantgar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-avantgar-20200406'},
    {'reference':'texlive-awesomebox-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-awesomebox-20180414'},
    {'reference':'texlive-awesomebox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-awesomebox-20200406'},
    {'reference':'texlive-babel-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-babel-20180414'},
    {'reference':'texlive-babel-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-babel-20200406'},
    {'reference':'texlive-babel-english-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-babel-english-20180414'},
    {'reference':'texlive-babel-english-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-babel-english-20200406'},
    {'reference':'texlive-babelbib-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-babelbib-20180414'},
    {'reference':'texlive-babelbib-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-babelbib-20200406'},
    {'reference':'texlive-base-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-base-20180414'},
    {'reference':'texlive-base-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-base-20200406'},
    {'reference':'texlive-beamer-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-beamer-20180414'},
    {'reference':'texlive-beamer-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-beamer-20200406'},
    {'reference':'texlive-bera-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bera-20180414'},
    {'reference':'texlive-bera-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bera-20200406'},
    {'reference':'texlive-beton-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-beton-20180414'},
    {'reference':'texlive-beton-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-beton-20200406'},
    {'reference':'texlive-bibtex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtex-20180414'},
    {'reference':'texlive-bibtex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtex-20180414'},
    {'reference':'texlive-bibtex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-20200406'},
    {'reference':'texlive-bibtex-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-20200406'},
    {'reference':'texlive-bibtex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-20200406'},
    {'reference':'texlive-bibtex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtex-debuginfo-20180414'},
    {'reference':'texlive-bibtex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtex-debuginfo-20180414'},
    {'reference':'texlive-bibtex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-debuginfo-20200406'},
    {'reference':'texlive-bibtex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-debuginfo-20200406'},
    {'reference':'texlive-bibtex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtex-debuginfo-20200406'},
    {'reference':'texlive-bibtopic-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bibtopic-20180414'},
    {'reference':'texlive-bibtopic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bibtopic-20200406'},
    {'reference':'texlive-bidi-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bidi-20180414'},
    {'reference':'texlive-bidi-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bidi-20200406'},
    {'reference':'texlive-bigfoot-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bigfoot-20180414'},
    {'reference':'texlive-bigfoot-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bigfoot-20200406'},
    {'reference':'texlive-bigintcalc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bitset-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bookman-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-bookman-20180414'},
    {'reference':'texlive-bookman-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-bookman-20200406'},
    {'reference':'texlive-bookmark-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-booktabs-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-booktabs-20180414'},
    {'reference':'texlive-booktabs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-booktabs-20200406'},
    {'reference':'texlive-breakurl-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-breakurl-20180414'},
    {'reference':'texlive-breakurl-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-breakurl-20200406'},
    {'reference':'texlive-breqn-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-breqn-20180414'},
    {'reference':'texlive-breqn-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-breqn-20200406'},
    {'reference':'texlive-capt-of-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-capt-of-20180414'},
    {'reference':'texlive-capt-of-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-capt-of-20200406'},
    {'reference':'texlive-caption-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-caption-20180414'},
    {'reference':'texlive-caption-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-caption-20200406'},
    {'reference':'texlive-carlisle-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-carlisle-20180414'},
    {'reference':'texlive-carlisle-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-carlisle-20200406'},
    {'reference':'texlive-catchfile-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-changebar-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-changebar-20180414'},
    {'reference':'texlive-changebar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-changebar-20200406'},
    {'reference':'texlive-changepage-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-changepage-20180414'},
    {'reference':'texlive-changepage-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-changepage-20200406'},
    {'reference':'texlive-charter-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-charter-20180414'},
    {'reference':'texlive-charter-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-charter-20200406'},
    {'reference':'texlive-chngcntr-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-chngcntr-20180414'},
    {'reference':'texlive-chngcntr-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-chngcntr-20200406'},
    {'reference':'texlive-cite-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cite-20180414'},
    {'reference':'texlive-cite-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cite-20200406'},
    {'reference':'texlive-cjk-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cjk-20180414'},
    {'reference':'texlive-cjk-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cjk-20200406'},
    {'reference':'texlive-classpack-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-classpack-20180414'},
    {'reference':'texlive-classpack-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-classpack-20200406'},
    {'reference':'texlive-cm-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cm-20180414'},
    {'reference':'texlive-cm-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cm-20200406'},
    {'reference':'texlive-cm-lgc-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cm-lgc-20180414'},
    {'reference':'texlive-cm-lgc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cm-lgc-20200406'},
    {'reference':'texlive-cm-super-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cm-super-20180414'},
    {'reference':'texlive-cm-super-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cm-super-20200406'},
    {'reference':'texlive-cmap-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cmap-20180414'},
    {'reference':'texlive-cmap-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cmap-20200406'},
    {'reference':'texlive-cmextra-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cmextra-20180414'},
    {'reference':'texlive-cmextra-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cmextra-20200406'},
    {'reference':'texlive-cns-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-cns-20180414'},
    {'reference':'texlive-cns-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-cns-20200406'},
    {'reference':'texlive-collectbox-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collectbox-20180414'},
    {'reference':'texlive-collectbox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collectbox-20200406'},
    {'reference':'texlive-collection-basic-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-basic-20180414'},
    {'reference':'texlive-collection-basic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-basic-20200406'},
    {'reference':'texlive-collection-fontsrecommended-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-fontsrecommended-20180414'},
    {'reference':'texlive-collection-fontsrecommended-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-fontsrecommended-20200406'},
    {'reference':'texlive-collection-htmlxml-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-htmlxml-20180414'},
    {'reference':'texlive-collection-htmlxml-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-htmlxml-20200406'},
    {'reference':'texlive-collection-latex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-latex-20180414'},
    {'reference':'texlive-collection-latex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-latex-20200406'},
    {'reference':'texlive-collection-latexrecommended-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-latexrecommended-20180414'},
    {'reference':'texlive-collection-latexrecommended-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-latexrecommended-20200406'},
    {'reference':'texlive-collection-xetex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-collection-xetex-20180414'},
    {'reference':'texlive-collection-xetex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-collection-xetex-20200406'},
    {'reference':'texlive-colorprofiles-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-colortbl-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-colortbl-20180414'},
    {'reference':'texlive-colortbl-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-colortbl-20200406'},
    {'reference':'texlive-context-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-context-20180414'},
    {'reference':'texlive-context-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-context-20200406'},
    {'reference':'texlive-courier-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-courier-20180414'},
    {'reference':'texlive-courier-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-courier-20200406'},
    {'reference':'texlive-crop-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-crop-20180414'},
    {'reference':'texlive-crop-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-crop-20200406'},
    {'reference':'texlive-csquotes-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-csquotes-20180414'},
    {'reference':'texlive-csquotes-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-csquotes-20200406'},
    {'reference':'texlive-ctable-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ctable-20180414'},
    {'reference':'texlive-ctable-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ctable-20200406'},
    {'reference':'texlive-ctablestack-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ctablestack-20180414'},
    {'reference':'texlive-ctablestack-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ctablestack-20200406'},
    {'reference':'texlive-currfile-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-currfile-20180414'},
    {'reference':'texlive-currfile-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-currfile-20200406'},
    {'reference':'texlive-datetime-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-datetime-20180414'},
    {'reference':'texlive-datetime-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-datetime-20200406'},
    {'reference':'texlive-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debuginfo-20180414'},
    {'reference':'texlive-debuginfo-20180414-29.el8_8', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debuginfo-20180414'},
    {'reference':'texlive-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debuginfo-20180414'},
    {'reference':'texlive-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debuginfo-20200406'},
    {'reference':'texlive-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debuginfo-20200406'},
    {'reference':'texlive-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debuginfo-20200406'},
    {'reference':'texlive-debugsource-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debugsource-20180414'},
    {'reference':'texlive-debugsource-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-debugsource-20180414'},
    {'reference':'texlive-debugsource-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debugsource-20200406'},
    {'reference':'texlive-debugsource-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debugsource-20200406'},
    {'reference':'texlive-debugsource-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-debugsource-20200406'},
    {'reference':'texlive-dehyph-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvipdfmx-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipdfmx-20180414'},
    {'reference':'texlive-dvipdfmx-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipdfmx-20180414'},
    {'reference':'texlive-dvipdfmx-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipdfmx-20200406'},
    {'reference':'texlive-dvipdfmx-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipdfmx-20200406'},
    {'reference':'texlive-dvipdfmx-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipdfmx-20200406'},
    {'reference':'texlive-dvipng-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipng-20180414'},
    {'reference':'texlive-dvipng-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipng-20180414'},
    {'reference':'texlive-dvipng-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-20200406'},
    {'reference':'texlive-dvipng-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-20200406'},
    {'reference':'texlive-dvipng-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-20200406'},
    {'reference':'texlive-dvipng-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipng-debuginfo-20180414'},
    {'reference':'texlive-dvipng-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvipng-debuginfo-20180414'},
    {'reference':'texlive-dvipng-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-debuginfo-20200406'},
    {'reference':'texlive-dvipng-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-debuginfo-20200406'},
    {'reference':'texlive-dvipng-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvipng-debuginfo-20200406'},
    {'reference':'texlive-dvips-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvips-20180414'},
    {'reference':'texlive-dvips-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvips-20180414'},
    {'reference':'texlive-dvips-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-20200406'},
    {'reference':'texlive-dvips-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-20200406'},
    {'reference':'texlive-dvips-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-20200406'},
    {'reference':'texlive-dvips-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvips-debuginfo-20180414'},
    {'reference':'texlive-dvips-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvips-debuginfo-20180414'},
    {'reference':'texlive-dvips-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-debuginfo-20200406'},
    {'reference':'texlive-dvips-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-debuginfo-20200406'},
    {'reference':'texlive-dvips-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvips-debuginfo-20200406'},
    {'reference':'texlive-dvisvgm-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvisvgm-20180414'},
    {'reference':'texlive-dvisvgm-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvisvgm-20180414'},
    {'reference':'texlive-dvisvgm-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-20200406'},
    {'reference':'texlive-dvisvgm-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-20200406'},
    {'reference':'texlive-dvisvgm-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-20200406'},
    {'reference':'texlive-dvisvgm-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvisvgm-debuginfo-20180414'},
    {'reference':'texlive-dvisvgm-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-dvisvgm-debuginfo-20180414'},
    {'reference':'texlive-dvisvgm-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-debuginfo-20200406'},
    {'reference':'texlive-dvisvgm-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-debuginfo-20200406'},
    {'reference':'texlive-dvisvgm-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-dvisvgm-debuginfo-20200406'},
    {'reference':'texlive-ec-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ec-20180414'},
    {'reference':'texlive-ec-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ec-20200406'},
    {'reference':'texlive-eepic-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-eepic-20180414'},
    {'reference':'texlive-eepic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-eepic-20200406'},
    {'reference':'texlive-enctex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-enctex-20180414'},
    {'reference':'texlive-enctex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-enctex-20200406'},
    {'reference':'texlive-enumitem-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-enumitem-20180414'},
    {'reference':'texlive-enumitem-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-enumitem-20200406'},
    {'reference':'texlive-environ-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-environ-20180414'},
    {'reference':'texlive-environ-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-environ-20200406'},
    {'reference':'texlive-epsf-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-epsf-20180414'},
    {'reference':'texlive-epsf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-epsf-20200406'},
    {'reference':'texlive-epstopdf-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-epstopdf-20180414'},
    {'reference':'texlive-epstopdf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-epstopdf-20200406'},
    {'reference':'texlive-epstopdf-pkg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eqparbox-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-eqparbox-20180414'},
    {'reference':'texlive-eqparbox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-eqparbox-20200406'},
    {'reference':'texlive-eso-pic-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-eso-pic-20180414'},
    {'reference':'texlive-eso-pic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-eso-pic-20200406'},
    {'reference':'texlive-etex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-etex-20180414'},
    {'reference':'texlive-etex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-etex-20200406'},
    {'reference':'texlive-etex-pkg-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-etex-pkg-20180414'},
    {'reference':'texlive-etex-pkg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-etex-pkg-20200406'},
    {'reference':'texlive-etexcmds-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etoc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etoolbox-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-etoolbox-20180414'},
    {'reference':'texlive-etoolbox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-etoolbox-20200406'},
    {'reference':'texlive-euenc-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-euenc-20180414'},
    {'reference':'texlive-euenc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-euenc-20200406'},
    {'reference':'texlive-euler-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-euler-20180414'},
    {'reference':'texlive-euler-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-euler-20200406'},
    {'reference':'texlive-euro-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-euro-20180414'},
    {'reference':'texlive-euro-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-euro-20200406'},
    {'reference':'texlive-eurosym-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-eurosym-20180414'},
    {'reference':'texlive-eurosym-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-eurosym-20200406'},
    {'reference':'texlive-extsizes-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-extsizes-20180414'},
    {'reference':'texlive-extsizes-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-extsizes-20200406'},
    {'reference':'texlive-fancybox-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fancybox-20180414'},
    {'reference':'texlive-fancybox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fancybox-20200406'},
    {'reference':'texlive-fancyhdr-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fancyhdr-20180414'},
    {'reference':'texlive-fancyhdr-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fancyhdr-20200406'},
    {'reference':'texlive-fancyref-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fancyref-20180414'},
    {'reference':'texlive-fancyref-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fancyref-20200406'},
    {'reference':'texlive-fancyvrb-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fancyvrb-20180414'},
    {'reference':'texlive-fancyvrb-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fancyvrb-20200406'},
    {'reference':'texlive-filecontents-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-filecontents-20180414'},
    {'reference':'texlive-filecontents-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-filecontents-20200406'},
    {'reference':'texlive-filehook-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-filehook-20180414'},
    {'reference':'texlive-filehook-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-filehook-20200406'},
    {'reference':'texlive-finstrut-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-finstrut-20180414'},
    {'reference':'texlive-finstrut-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-finstrut-20200406'},
    {'reference':'texlive-fix2col-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fix2col-20180414'},
    {'reference':'texlive-fix2col-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fix2col-20200406'},
    {'reference':'texlive-fixlatvian-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fixlatvian-20180414'},
    {'reference':'texlive-fixlatvian-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fixlatvian-20200406'},
    {'reference':'texlive-float-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-float-20180414'},
    {'reference':'texlive-float-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-float-20200406'},
    {'reference':'texlive-fmtcount-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fmtcount-20180414'},
    {'reference':'texlive-fmtcount-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fmtcount-20200406'},
    {'reference':'texlive-fncychap-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fncychap-20180414'},
    {'reference':'texlive-fncychap-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fncychap-20200406'},
    {'reference':'texlive-fontawesome-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontawesome-20180414'},
    {'reference':'texlive-fontawesome-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontawesome-20200406'},
    {'reference':'texlive-fontbook-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontbook-20180414'},
    {'reference':'texlive-fontbook-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontbook-20200406'},
    {'reference':'texlive-fonts-tlwg-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fonts-tlwg-20180414'},
    {'reference':'texlive-fonts-tlwg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fonts-tlwg-20200406'},
    {'reference':'texlive-fontspec-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontspec-20180414'},
    {'reference':'texlive-fontspec-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontspec-20200406'},
    {'reference':'texlive-fontware-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontware-20180414'},
    {'reference':'texlive-fontware-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontware-20180414'},
    {'reference':'texlive-fontware-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-20200406'},
    {'reference':'texlive-fontware-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-20200406'},
    {'reference':'texlive-fontware-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-20200406'},
    {'reference':'texlive-fontware-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontware-debuginfo-20180414'},
    {'reference':'texlive-fontware-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontware-debuginfo-20180414'},
    {'reference':'texlive-fontware-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-debuginfo-20200406'},
    {'reference':'texlive-fontware-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-debuginfo-20200406'},
    {'reference':'texlive-fontware-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontware-debuginfo-20200406'},
    {'reference':'texlive-fontwrap-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fontwrap-20180414'},
    {'reference':'texlive-fontwrap-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fontwrap-20200406'},
    {'reference':'texlive-footmisc-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-footmisc-20180414'},
    {'reference':'texlive-footmisc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-footmisc-20200406'},
    {'reference':'texlive-footnotehyper-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fp-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fp-20180414'},
    {'reference':'texlive-fp-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fp-20200406'},
    {'reference':'texlive-fpl-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-fpl-20180414'},
    {'reference':'texlive-fpl-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-fpl-20200406'},
    {'reference':'texlive-framed-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-framed-20180414'},
    {'reference':'texlive-framed-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-framed-20200406'},
    {'reference':'texlive-garuda-c90-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-garuda-c90-20180414'},
    {'reference':'texlive-garuda-c90-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-garuda-c90-20200406'},
    {'reference':'texlive-geometry-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-geometry-20180414'},
    {'reference':'texlive-geometry-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-geometry-20200406'},
    {'reference':'texlive-gettitlestring-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-glyphlist-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-glyphlist-20180414'},
    {'reference':'texlive-glyphlist-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-glyphlist-20200406'},
    {'reference':'texlive-gnu-freefont-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-graphics-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-graphics-20180414'},
    {'reference':'texlive-graphics-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-graphics-20200406'},
    {'reference':'texlive-graphics-cfg-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-graphics-cfg-20180414'},
    {'reference':'texlive-graphics-cfg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-graphics-cfg-20200406'},
    {'reference':'texlive-graphics-def-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-graphics-def-20180414'},
    {'reference':'texlive-graphics-def-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-graphics-def-20200406'},
    {'reference':'texlive-grfext-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-grffile-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-gsftopk-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-gsftopk-20180414'},
    {'reference':'texlive-gsftopk-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-gsftopk-20180414'},
    {'reference':'texlive-gsftopk-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-20200406'},
    {'reference':'texlive-gsftopk-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-20200406'},
    {'reference':'texlive-gsftopk-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-20200406'},
    {'reference':'texlive-gsftopk-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-gsftopk-debuginfo-20180414'},
    {'reference':'texlive-gsftopk-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-gsftopk-debuginfo-20180414'},
    {'reference':'texlive-gsftopk-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-debuginfo-20200406'},
    {'reference':'texlive-gsftopk-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-debuginfo-20200406'},
    {'reference':'texlive-gsftopk-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-gsftopk-debuginfo-20200406'},
    {'reference':'texlive-hanging-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-helvetic-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-helvetic-20180414'},
    {'reference':'texlive-helvetic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-helvetic-20200406'},
    {'reference':'texlive-hobsub-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hologo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hycolor-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyperref-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-hyperref-20180414'},
    {'reference':'texlive-hyperref-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-hyperref-20200406'},
    {'reference':'texlive-hyph-utf8-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-hyph-utf8-20180414'},
    {'reference':'texlive-hyph-utf8-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-hyph-utf8-20200406'},
    {'reference':'texlive-hyphen-base-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-hyphen-base-20180414'},
    {'reference':'texlive-hyphen-base-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-hyphen-base-20200406'},
    {'reference':'texlive-hyphenat-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-hyphenat-20180414'},
    {'reference':'texlive-hyphenat-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-hyphenat-20200406'},
    {'reference':'texlive-hyphenex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ifetex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifluatex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifmtarg-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ifmtarg-20180414'},
    {'reference':'texlive-ifmtarg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ifmtarg-20200406'},
    {'reference':'texlive-ifoddpage-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ifoddpage-20180414'},
    {'reference':'texlive-ifoddpage-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ifoddpage-20200406'},
    {'reference':'texlive-ifplatform-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-iftex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-iftex-20180414'},
    {'reference':'texlive-iftex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-iftex-20200406'},
    {'reference':'texlive-ifxetex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-import-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-import-20180414'},
    {'reference':'texlive-import-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-import-20200406'},
    {'reference':'texlive-index-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-index-20180414'},
    {'reference':'texlive-index-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-index-20200406'},
    {'reference':'texlive-infwarerr-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-intcalc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-jadetex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-jadetex-20180414'},
    {'reference':'texlive-jadetex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-jadetex-20200406'},
    {'reference':'texlive-jknapltx-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-jknapltx-20180414'},
    {'reference':'texlive-jknapltx-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-jknapltx-20200406'},
    {'reference':'texlive-kastrup-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kastrup-20180414'},
    {'reference':'texlive-kastrup-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kastrup-20200406'},
    {'reference':'texlive-kerkis-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kerkis-20180414'},
    {'reference':'texlive-kerkis-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kerkis-20200406'},
    {'reference':'texlive-knuth-lib-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-knuth-lib-20180414'},
    {'reference':'texlive-knuth-lib-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-knuth-lib-20200406'},
    {'reference':'texlive-knuth-local-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-knuth-local-20180414'},
    {'reference':'texlive-knuth-local-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-knuth-local-20200406'},
    {'reference':'texlive-koma-script-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-koma-script-20180414'},
    {'reference':'texlive-koma-script-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-koma-script-20200406'},
    {'reference':'texlive-kpathsea-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kpathsea-20180414'},
    {'reference':'texlive-kpathsea-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kpathsea-20180414'},
    {'reference':'texlive-kpathsea-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-20200406'},
    {'reference':'texlive-kpathsea-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-20200406'},
    {'reference':'texlive-kpathsea-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-20200406'},
    {'reference':'texlive-kpathsea-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kpathsea-debuginfo-20180414'},
    {'reference':'texlive-kpathsea-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-kpathsea-debuginfo-20180414'},
    {'reference':'texlive-kpathsea-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-debuginfo-20200406'},
    {'reference':'texlive-kpathsea-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-debuginfo-20200406'},
    {'reference':'texlive-kpathsea-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-kpathsea-debuginfo-20200406'},
    {'reference':'texlive-kvdefinekeys-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvoptions-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvsetkeys-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3backend-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3experimental-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-l3experimental-20180414'},
    {'reference':'texlive-l3experimental-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-l3experimental-20200406'},
    {'reference':'texlive-l3kernel-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-l3kernel-20180414'},
    {'reference':'texlive-l3kernel-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-l3kernel-20200406'},
    {'reference':'texlive-l3packages-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-l3packages-20180414'},
    {'reference':'texlive-l3packages-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-l3packages-20200406'},
    {'reference':'texlive-lastpage-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lastpage-20180414'},
    {'reference':'texlive-lastpage-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lastpage-20200406'},
    {'reference':'texlive-latex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-latex-20180414'},
    {'reference':'texlive-latex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-latex-20200406'},
    {'reference':'texlive-latex-fonts-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-latex-fonts-20180414'},
    {'reference':'texlive-latex-fonts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-latex-fonts-20200406'},
    {'reference':'texlive-latex2man-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-latex2man-20180414'},
    {'reference':'texlive-latex2man-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-latex2man-20200406'},
    {'reference':'texlive-latexbug-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latexconfig-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-latexconfig-20180414'},
    {'reference':'texlive-latexconfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-latexconfig-20200406'},
    {'reference':'texlive-letltxmacro-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lettrine-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lettrine-20180414'},
    {'reference':'texlive-lettrine-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lettrine-20200406'},
    {'reference':'texlive-lib-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-20180414'},
    {'reference':'texlive-lib-20180414-29.el8_8', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-20180414'},
    {'reference':'texlive-lib-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-20180414'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-20200406'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-20200406'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-20200406'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-20200406'},
    {'reference':'texlive-lib-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-debuginfo-20180414'},
    {'reference':'texlive-lib-debuginfo-20180414-29.el8_8', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-debuginfo-20180414'},
    {'reference':'texlive-lib-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-debuginfo-20180414'},
    {'reference':'texlive-lib-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-debuginfo-20200406'},
    {'reference':'texlive-lib-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-debuginfo-20200406'},
    {'reference':'texlive-lib-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-debuginfo-20200406'},
    {'reference':'texlive-lib-devel-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-devel-20180414'},
    {'reference':'texlive-lib-devel-20180414-29.el8_8', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-devel-20180414'},
    {'reference':'texlive-lib-devel-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lib-devel-20180414'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-devel-20200406'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-devel-20200406'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-devel-20200406'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lib-devel-20200406'},
    {'reference':'texlive-linegoal-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-linegoal-20180414'},
    {'reference':'texlive-linegoal-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-linegoal-20200406'},
    {'reference':'texlive-lineno-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lineno-20180414'},
    {'reference':'texlive-lineno-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lineno-20200406'},
    {'reference':'texlive-listings-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-listings-20180414'},
    {'reference':'texlive-listings-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-listings-20200406'},
    {'reference':'texlive-listofitems-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lm-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lm-20180414'},
    {'reference':'texlive-lm-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lm-20200406'},
    {'reference':'texlive-lm-math-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lm-math-20180414'},
    {'reference':'texlive-lm-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lm-math-20200406'},
    {'reference':'texlive-ltabptch-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ltabptch-20180414'},
    {'reference':'texlive-ltabptch-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ltabptch-20200406'},
    {'reference':'texlive-ltxcmds-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ltxmisc-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ltxmisc-20180414'},
    {'reference':'texlive-ltxmisc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ltxmisc-20200406'},
    {'reference':'texlive-lua-alt-getopt-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lua-alt-getopt-20180414'},
    {'reference':'texlive-lua-alt-getopt-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lua-alt-getopt-20200406'},
    {'reference':'texlive-luahbtex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lualatex-math-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lualatex-math-20180414'},
    {'reference':'texlive-lualatex-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lualatex-math-20200406'},
    {'reference':'texlive-lualibs-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-lualibs-20180414'},
    {'reference':'texlive-lualibs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-lualibs-20200406'},
    {'reference':'texlive-luaotfload-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luaotfload-20180414'},
    {'reference':'texlive-luaotfload-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luaotfload-20200406'},
    {'reference':'texlive-luatex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex-20180414'},
    {'reference':'texlive-luatex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex-20180414'},
    {'reference':'texlive-luatex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-20200406'},
    {'reference':'texlive-luatex-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-20200406'},
    {'reference':'texlive-luatex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-20200406'},
    {'reference':'texlive-luatex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex-debuginfo-20180414'},
    {'reference':'texlive-luatex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex-debuginfo-20180414'},
    {'reference':'texlive-luatex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-debuginfo-20200406'},
    {'reference':'texlive-luatex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-debuginfo-20200406'},
    {'reference':'texlive-luatex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex-debuginfo-20200406'},
    {'reference':'texlive-luatex85-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatex85-20180414'},
    {'reference':'texlive-luatex85-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatex85-20200406'},
    {'reference':'texlive-luatexbase-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-luatexbase-20180414'},
    {'reference':'texlive-luatexbase-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-luatexbase-20200406'},
    {'reference':'texlive-lwarp-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-makecmds-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makecmds-20180414'},
    {'reference':'texlive-makecmds-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makecmds-20200406'},
    {'reference':'texlive-makeindex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makeindex-20180414'},
    {'reference':'texlive-makeindex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makeindex-20180414'},
    {'reference':'texlive-makeindex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-20200406'},
    {'reference':'texlive-makeindex-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-20200406'},
    {'reference':'texlive-makeindex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-20200406'},
    {'reference':'texlive-makeindex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makeindex-debuginfo-20180414'},
    {'reference':'texlive-makeindex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-makeindex-debuginfo-20180414'},
    {'reference':'texlive-makeindex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-debuginfo-20200406'},
    {'reference':'texlive-makeindex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-debuginfo-20200406'},
    {'reference':'texlive-makeindex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-makeindex-debuginfo-20200406'},
    {'reference':'texlive-manfnt-font-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-manfnt-font-20180414'},
    {'reference':'texlive-manfnt-font-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-manfnt-font-20200406'},
    {'reference':'texlive-marginnote-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-marginnote-20180414'},
    {'reference':'texlive-marginnote-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-marginnote-20200406'},
    {'reference':'texlive-marvosym-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-marvosym-20180414'},
    {'reference':'texlive-marvosym-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-marvosym-20200406'},
    {'reference':'texlive-mathpazo-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mathpazo-20180414'},
    {'reference':'texlive-mathpazo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mathpazo-20200406'},
    {'reference':'texlive-mathspec-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mathspec-20180414'},
    {'reference':'texlive-mathspec-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mathspec-20200406'},
    {'reference':'texlive-mathtools-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mathtools-20180414'},
    {'reference':'texlive-mathtools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mathtools-20200406'},
    {'reference':'texlive-mdwtools-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mdwtools-20180414'},
    {'reference':'texlive-mdwtools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mdwtools-20200406'},
    {'reference':'texlive-memoir-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-memoir-20180414'},
    {'reference':'texlive-memoir-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-memoir-20200406'},
    {'reference':'texlive-metafont-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metafont-20180414'},
    {'reference':'texlive-metafont-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metafont-20180414'},
    {'reference':'texlive-metafont-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-20200406'},
    {'reference':'texlive-metafont-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-20200406'},
    {'reference':'texlive-metafont-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-20200406'},
    {'reference':'texlive-metafont-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metafont-debuginfo-20180414'},
    {'reference':'texlive-metafont-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metafont-debuginfo-20180414'},
    {'reference':'texlive-metafont-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-debuginfo-20200406'},
    {'reference':'texlive-metafont-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-debuginfo-20200406'},
    {'reference':'texlive-metafont-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metafont-debuginfo-20200406'},
    {'reference':'texlive-metalogo-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metalogo-20180414'},
    {'reference':'texlive-metalogo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metalogo-20200406'},
    {'reference':'texlive-metapost-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metapost-20180414'},
    {'reference':'texlive-metapost-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metapost-20180414'},
    {'reference':'texlive-metapost-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-20200406'},
    {'reference':'texlive-metapost-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-20200406'},
    {'reference':'texlive-metapost-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-20200406'},
    {'reference':'texlive-metapost-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metapost-debuginfo-20180414'},
    {'reference':'texlive-metapost-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-metapost-debuginfo-20180414'},
    {'reference':'texlive-metapost-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-debuginfo-20200406'},
    {'reference':'texlive-metapost-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-debuginfo-20200406'},
    {'reference':'texlive-metapost-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-metapost-debuginfo-20200406'},
    {'reference':'texlive-mflogo-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mflogo-20180414'},
    {'reference':'texlive-mflogo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mflogo-20200406'},
    {'reference':'texlive-mflogo-font-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mflogo-font-20180414'},
    {'reference':'texlive-mflogo-font-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mflogo-font-20200406'},
    {'reference':'texlive-mfnfss-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfnfss-20180414'},
    {'reference':'texlive-mfnfss-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfnfss-20200406'},
    {'reference':'texlive-mfware-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfware-20180414'},
    {'reference':'texlive-mfware-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfware-20180414'},
    {'reference':'texlive-mfware-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-20200406'},
    {'reference':'texlive-mfware-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-20200406'},
    {'reference':'texlive-mfware-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-20200406'},
    {'reference':'texlive-mfware-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfware-debuginfo-20180414'},
    {'reference':'texlive-mfware-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mfware-debuginfo-20180414'},
    {'reference':'texlive-mfware-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-debuginfo-20200406'},
    {'reference':'texlive-mfware-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-debuginfo-20200406'},
    {'reference':'texlive-mfware-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mfware-debuginfo-20200406'},
    {'reference':'texlive-microtype-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-microtype-20180414'},
    {'reference':'texlive-microtype-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-microtype-20200406'},
    {'reference':'texlive-minitoc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mnsymbol-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mnsymbol-20180414'},
    {'reference':'texlive-mnsymbol-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mnsymbol-20200406'},
    {'reference':'texlive-modes-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mparhack-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mparhack-20180414'},
    {'reference':'texlive-mparhack-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mparhack-20200406'},
    {'reference':'texlive-mptopdf-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-mptopdf-20180414'},
    {'reference':'texlive-mptopdf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-mptopdf-20200406'},
    {'reference':'texlive-ms-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ms-20180414'},
    {'reference':'texlive-ms-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ms-20200406'},
    {'reference':'texlive-multido-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-multido-20180414'},
    {'reference':'texlive-multido-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-multido-20200406'},
    {'reference':'texlive-multirow-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-multirow-20180414'},
    {'reference':'texlive-multirow-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-multirow-20200406'},
    {'reference':'texlive-natbib-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-natbib-20180414'},
    {'reference':'texlive-natbib-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-natbib-20200406'},
    {'reference':'texlive-ncctools-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ncctools-20180414'},
    {'reference':'texlive-ncctools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ncctools-20200406'},
    {'reference':'texlive-ncntrsbk-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ncntrsbk-20180414'},
    {'reference':'texlive-ncntrsbk-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ncntrsbk-20200406'},
    {'reference':'texlive-needspace-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-needspace-20180414'},
    {'reference':'texlive-needspace-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-needspace-20200406'},
    {'reference':'texlive-newfloat-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-newunicodechar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-norasi-c90-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-norasi-c90-20180414'},
    {'reference':'texlive-norasi-c90-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-norasi-c90-20200406'},
    {'reference':'texlive-notoccite-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ntgclass-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ntgclass-20180414'},
    {'reference':'texlive-ntgclass-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ntgclass-20200406'},
    {'reference':'texlive-oberdiek-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-oberdiek-20180414'},
    {'reference':'texlive-oberdiek-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-oberdiek-20200406'},
    {'reference':'texlive-obsolete-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-overpic-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-overpic-20180414'},
    {'reference':'texlive-overpic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-overpic-20200406'},
    {'reference':'texlive-palatino-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-palatino-20180414'},
    {'reference':'texlive-palatino-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-palatino-20200406'},
    {'reference':'texlive-paralist-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-paralist-20180414'},
    {'reference':'texlive-paralist-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-paralist-20200406'},
    {'reference':'texlive-parallel-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-parallel-20180414'},
    {'reference':'texlive-parallel-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-parallel-20200406'},
    {'reference':'texlive-parskip-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-parskip-20180414'},
    {'reference':'texlive-parskip-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-parskip-20200406'},
    {'reference':'texlive-passivetex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-passivetex-20180414'},
    {'reference':'texlive-passivetex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-passivetex-20200406'},
    {'reference':'texlive-pdfcolmk-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfescape-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdflscape-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfpages-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdfpages-20180414'},
    {'reference':'texlive-pdfpages-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdfpages-20200406'},
    {'reference':'texlive-pdftex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdftex-20180414'},
    {'reference':'texlive-pdftex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdftex-20180414'},
    {'reference':'texlive-pdftex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-20200406'},
    {'reference':'texlive-pdftex-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-20200406'},
    {'reference':'texlive-pdftex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-20200406'},
    {'reference':'texlive-pdftex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdftex-debuginfo-20180414'},
    {'reference':'texlive-pdftex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pdftex-debuginfo-20180414'},
    {'reference':'texlive-pdftex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-debuginfo-20200406'},
    {'reference':'texlive-pdftex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-debuginfo-20200406'},
    {'reference':'texlive-pdftex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pdftex-debuginfo-20200406'},
    {'reference':'texlive-pdftexcmds-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pgf-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pgf-20180414'},
    {'reference':'texlive-pgf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pgf-20200406'},
    {'reference':'texlive-philokalia-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-philokalia-20180414'},
    {'reference':'texlive-philokalia-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-philokalia-20200406'},
    {'reference':'texlive-placeins-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-placeins-20180414'},
    {'reference':'texlive-placeins-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-placeins-20200406'},
    {'reference':'texlive-plain-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-plain-20180414'},
    {'reference':'texlive-plain-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-plain-20200406'},
    {'reference':'texlive-polyglossia-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-polyglossia-20180414'},
    {'reference':'texlive-polyglossia-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-polyglossia-20200406'},
    {'reference':'texlive-powerdot-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-powerdot-20180414'},
    {'reference':'texlive-powerdot-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-powerdot-20200406'},
    {'reference':'texlive-preprint-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-preprint-20180414'},
    {'reference':'texlive-preprint-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-preprint-20200406'},
    {'reference':'texlive-psfrag-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-psfrag-20180414'},
    {'reference':'texlive-psfrag-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-psfrag-20200406'},
    {'reference':'texlive-pslatex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pslatex-20180414'},
    {'reference':'texlive-pslatex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pslatex-20200406'},
    {'reference':'texlive-psnfss-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-psnfss-20180414'},
    {'reference':'texlive-psnfss-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-psnfss-20200406'},
    {'reference':'texlive-pspicture-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pspicture-20180414'},
    {'reference':'texlive-pspicture-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pspicture-20200406'},
    {'reference':'texlive-pst-3d-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-3d-20180414'},
    {'reference':'texlive-pst-3d-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-3d-20200406'},
    {'reference':'texlive-pst-arrow-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-arrow-20180414'},
    {'reference':'texlive-pst-arrow-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-arrow-20200406'},
    {'reference':'texlive-pst-blur-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-blur-20180414'},
    {'reference':'texlive-pst-blur-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-blur-20200406'},
    {'reference':'texlive-pst-coil-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-coil-20180414'},
    {'reference':'texlive-pst-coil-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-coil-20200406'},
    {'reference':'texlive-pst-eps-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-eps-20180414'},
    {'reference':'texlive-pst-eps-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-eps-20200406'},
    {'reference':'texlive-pst-fill-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-fill-20180414'},
    {'reference':'texlive-pst-fill-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-fill-20200406'},
    {'reference':'texlive-pst-grad-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-grad-20180414'},
    {'reference':'texlive-pst-grad-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-grad-20200406'},
    {'reference':'texlive-pst-math-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-math-20180414'},
    {'reference':'texlive-pst-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-math-20200406'},
    {'reference':'texlive-pst-node-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-node-20180414'},
    {'reference':'texlive-pst-node-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-node-20200406'},
    {'reference':'texlive-pst-plot-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-plot-20180414'},
    {'reference':'texlive-pst-plot-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-plot-20200406'},
    {'reference':'texlive-pst-slpe-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-slpe-20180414'},
    {'reference':'texlive-pst-slpe-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-slpe-20200406'},
    {'reference':'texlive-pst-text-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-text-20180414'},
    {'reference':'texlive-pst-text-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-text-20200406'},
    {'reference':'texlive-pst-tools-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-tools-20180414'},
    {'reference':'texlive-pst-tools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-tools-20200406'},
    {'reference':'texlive-pst-tree-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pst-tree-20180414'},
    {'reference':'texlive-pst-tree-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pst-tree-20200406'},
    {'reference':'texlive-pstricks-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pstricks-20180414'},
    {'reference':'texlive-pstricks-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pstricks-20200406'},
    {'reference':'texlive-pstricks-add-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pstricks-add-20180414'},
    {'reference':'texlive-pstricks-add-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pstricks-add-20200406'},
    {'reference':'texlive-ptext-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ptext-20180414'},
    {'reference':'texlive-ptext-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ptext-20200406'},
    {'reference':'texlive-pxfonts-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-pxfonts-20180414'},
    {'reference':'texlive-pxfonts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-pxfonts-20200406'},
    {'reference':'texlive-qstest-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-qstest-20180414'},
    {'reference':'texlive-qstest-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-qstest-20200406'},
    {'reference':'texlive-ragged2e-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rcs-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-rcs-20180414'},
    {'reference':'texlive-rcs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-rcs-20200406'},
    {'reference':'texlive-realscripts-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-realscripts-20180414'},
    {'reference':'texlive-realscripts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-realscripts-20200406'},
    {'reference':'texlive-refcount-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rerunfilecheck-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rsfs-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-rsfs-20180414'},
    {'reference':'texlive-rsfs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-rsfs-20200406'},
    {'reference':'texlive-sansmath-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-sansmath-20180414'},
    {'reference':'texlive-sansmath-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-sansmath-20200406'},
    {'reference':'texlive-sansmathaccent-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sauerj-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-sauerj-20180414'},
    {'reference':'texlive-sauerj-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-sauerj-20200406'},
    {'reference':'texlive-scheme-basic-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-scheme-basic-20180414'},
    {'reference':'texlive-scheme-basic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-scheme-basic-20200406'},
    {'reference':'texlive-section-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-section-20180414'},
    {'reference':'texlive-section-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-section-20200406'},
    {'reference':'texlive-sectsty-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-sectsty-20180414'},
    {'reference':'texlive-sectsty-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-sectsty-20200406'},
    {'reference':'texlive-seminar-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-seminar-20180414'},
    {'reference':'texlive-seminar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-seminar-20200406'},
    {'reference':'texlive-sepnum-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-sepnum-20180414'},
    {'reference':'texlive-sepnum-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-sepnum-20200406'},
    {'reference':'texlive-setspace-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-setspace-20180414'},
    {'reference':'texlive-setspace-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-setspace-20200406'},
    {'reference':'texlive-showexpl-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-showexpl-20180414'},
    {'reference':'texlive-showexpl-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-showexpl-20200406'},
    {'reference':'texlive-soul-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-soul-20180414'},
    {'reference':'texlive-soul-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-soul-20200406'},
    {'reference':'texlive-stackengine-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-stmaryrd-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-stmaryrd-20180414'},
    {'reference':'texlive-stmaryrd-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-stmaryrd-20200406'},
    {'reference':'texlive-stringenc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-subfig-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-subfig-20180414'},
    {'reference':'texlive-subfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-subfig-20200406'},
    {'reference':'texlive-subfigure-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-subfigure-20180414'},
    {'reference':'texlive-subfigure-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-subfigure-20200406'},
    {'reference':'texlive-svn-prov-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-svn-prov-20180414'},
    {'reference':'texlive-svn-prov-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-svn-prov-20200406'},
    {'reference':'texlive-symbol-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-symbol-20180414'},
    {'reference':'texlive-symbol-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-symbol-20200406'},
    {'reference':'texlive-t2-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-t2-20180414'},
    {'reference':'texlive-t2-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-t2-20200406'},
    {'reference':'texlive-tabu-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tabu-20180414'},
    {'reference':'texlive-tabu-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tabu-20200406'},
    {'reference':'texlive-tabulary-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tabulary-20180414'},
    {'reference':'texlive-tabulary-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tabulary-20200406'},
    {'reference':'texlive-tetex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-20180414'},
    {'reference':'texlive-tex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-20180414'},
    {'reference':'texlive-tex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-20200406'},
    {'reference':'texlive-tex-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-20200406'},
    {'reference':'texlive-tex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-20200406'},
    {'reference':'texlive-tex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-debuginfo-20180414'},
    {'reference':'texlive-tex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-debuginfo-20180414'},
    {'reference':'texlive-tex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-debuginfo-20200406'},
    {'reference':'texlive-tex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-debuginfo-20200406'},
    {'reference':'texlive-tex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-debuginfo-20200406'},
    {'reference':'texlive-tex-gyre-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-gyre-20180414'},
    {'reference':'texlive-tex-gyre-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-gyre-20200406'},
    {'reference':'texlive-tex-gyre-math-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-gyre-math-20180414'},
    {'reference':'texlive-tex-gyre-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-gyre-math-20200406'},
    {'reference':'texlive-tex-ini-files-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex-ini-files-20180414'},
    {'reference':'texlive-tex-ini-files-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex-ini-files-20200406'},
    {'reference':'texlive-tex4ht-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex4ht-20180414'},
    {'reference':'texlive-tex4ht-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex4ht-20180414'},
    {'reference':'texlive-tex4ht-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-20200406'},
    {'reference':'texlive-tex4ht-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-20200406'},
    {'reference':'texlive-tex4ht-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-20200406'},
    {'reference':'texlive-tex4ht-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex4ht-debuginfo-20180414'},
    {'reference':'texlive-tex4ht-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tex4ht-debuginfo-20180414'},
    {'reference':'texlive-tex4ht-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-debuginfo-20200406'},
    {'reference':'texlive-tex4ht-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-debuginfo-20200406'},
    {'reference':'texlive-tex4ht-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tex4ht-debuginfo-20200406'},
    {'reference':'texlive-texconfig-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-common-doc-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-common-doc-20180414'},
    {'reference':'texlive-texlive-common-doc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-common-doc-20200406'},
    {'reference':'texlive-texlive-docindex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-docindex-20180414'},
    {'reference':'texlive-texlive-docindex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-docindex-20200406'},
    {'reference':'texlive-texlive-en-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-en-20180414'},
    {'reference':'texlive-texlive-en-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-en-20200406'},
    {'reference':'texlive-texlive-msg-translations-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-msg-translations-20180414'},
    {'reference':'texlive-texlive-msg-translations-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-msg-translations-20200406'},
    {'reference':'texlive-texlive-scripts-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive-scripts-20180414'},
    {'reference':'texlive-texlive-scripts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive-scripts-20200406'},
    {'reference':'texlive-texlive-scripts-extra-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive.infra-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-texlive.infra-20180414'},
    {'reference':'texlive-texlive.infra-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-texlive.infra-20200406'},
    {'reference':'texlive-textcase-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-textcase-20180414'},
    {'reference':'texlive-textcase-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-textcase-20200406'},
    {'reference':'texlive-textpos-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-textpos-20180414'},
    {'reference':'texlive-textpos-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-textpos-20200406'},
    {'reference':'texlive-threeparttable-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-threeparttable-20180414'},
    {'reference':'texlive-threeparttable-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-threeparttable-20200406'},
    {'reference':'texlive-thumbpdf-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-thumbpdf-20180414'},
    {'reference':'texlive-thumbpdf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-thumbpdf-20200406'},
    {'reference':'texlive-times-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-times-20180414'},
    {'reference':'texlive-times-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-times-20200406'},
    {'reference':'texlive-tipa-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tipa-20180414'},
    {'reference':'texlive-tipa-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tipa-20200406'},
    {'reference':'texlive-titlesec-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-titlesec-20180414'},
    {'reference':'texlive-titlesec-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-titlesec-20200406'},
    {'reference':'texlive-titling-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-titling-20180414'},
    {'reference':'texlive-titling-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-titling-20200406'},
    {'reference':'texlive-tocloft-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tocloft-20180414'},
    {'reference':'texlive-tocloft-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tocloft-20200406'},
    {'reference':'texlive-tools-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-tools-20180414'},
    {'reference':'texlive-tools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-tools-20200406'},
    {'reference':'texlive-translator-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-translator-20180414'},
    {'reference':'texlive-translator-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-translator-20200406'},
    {'reference':'texlive-trimspaces-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-trimspaces-20180414'},
    {'reference':'texlive-trimspaces-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-trimspaces-20200406'},
    {'reference':'texlive-txfonts-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-txfonts-20180414'},
    {'reference':'texlive-txfonts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-txfonts-20200406'},
    {'reference':'texlive-type1cm-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-type1cm-20180414'},
    {'reference':'texlive-type1cm-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-type1cm-20200406'},
    {'reference':'texlive-typehtml-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-typehtml-20180414'},
    {'reference':'texlive-typehtml-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-typehtml-20200406'},
    {'reference':'texlive-ucharcat-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ucharclasses-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ucharclasses-20180414'},
    {'reference':'texlive-ucharclasses-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ucharclasses-20200406'},
    {'reference':'texlive-ucs-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ucs-20180414'},
    {'reference':'texlive-ucs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ucs-20200406'},
    {'reference':'texlive-uhc-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-uhc-20180414'},
    {'reference':'texlive-uhc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-uhc-20200406'},
    {'reference':'texlive-ulem-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-ulem-20180414'},
    {'reference':'texlive-ulem-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-ulem-20200406'},
    {'reference':'texlive-underscore-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-underscore-20180414'},
    {'reference':'texlive-underscore-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-underscore-20200406'},
    {'reference':'texlive-unicode-data-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-unicode-data-20180414'},
    {'reference':'texlive-unicode-data-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-unicode-data-20200406'},
    {'reference':'texlive-unicode-math-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-unicode-math-20180414'},
    {'reference':'texlive-unicode-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-unicode-math-20200406'},
    {'reference':'texlive-uniquecounter-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-unisugar-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-unisugar-20180414'},
    {'reference':'texlive-unisugar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-unisugar-20200406'},
    {'reference':'texlive-updmap-map-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-updmap-map-20180414'},
    {'reference':'texlive-updmap-map-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-updmap-map-20200406'},
    {'reference':'texlive-upquote-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-upquote-20180414'},
    {'reference':'texlive-upquote-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-upquote-20200406'},
    {'reference':'texlive-url-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-url-20180414'},
    {'reference':'texlive-url-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-url-20200406'},
    {'reference':'texlive-utopia-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-utopia-20180414'},
    {'reference':'texlive-utopia-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-utopia-20200406'},
    {'reference':'texlive-varwidth-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-varwidth-20180414'},
    {'reference':'texlive-varwidth-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-varwidth-20200406'},
    {'reference':'texlive-wadalab-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-wadalab-20180414'},
    {'reference':'texlive-wadalab-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-wadalab-20200406'},
    {'reference':'texlive-was-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-was-20180414'},
    {'reference':'texlive-was-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-was-20200406'},
    {'reference':'texlive-wasy-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-wasy-20180414'},
    {'reference':'texlive-wasy-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-wasy-20200406'},
    {'reference':'texlive-wasy-type1-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wasy2-ps-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasysym-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-wasysym-20180414'},
    {'reference':'texlive-wasysym-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-wasysym-20200406'},
    {'reference':'texlive-wrapfig-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-wrapfig-20180414'},
    {'reference':'texlive-wrapfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-wrapfig-20200406'},
    {'reference':'texlive-xcolor-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xcolor-20180414'},
    {'reference':'texlive-xcolor-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xcolor-20200406'},
    {'reference':'texlive-xdvi-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xdvi-20180414'},
    {'reference':'texlive-xdvi-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xdvi-20180414'},
    {'reference':'texlive-xdvi-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-20200406'},
    {'reference':'texlive-xdvi-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-20200406'},
    {'reference':'texlive-xdvi-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-20200406'},
    {'reference':'texlive-xdvi-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xdvi-debuginfo-20180414'},
    {'reference':'texlive-xdvi-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xdvi-debuginfo-20180414'},
    {'reference':'texlive-xdvi-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-debuginfo-20200406'},
    {'reference':'texlive-xdvi-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-debuginfo-20200406'},
    {'reference':'texlive-xdvi-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xdvi-debuginfo-20200406'},
    {'reference':'texlive-xecjk-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xecjk-20180414'},
    {'reference':'texlive-xecjk-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xecjk-20200406'},
    {'reference':'texlive-xecolor-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xecolor-20180414'},
    {'reference':'texlive-xecolor-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xecolor-20200406'},
    {'reference':'texlive-xecyr-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xecyr-20180414'},
    {'reference':'texlive-xecyr-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xecyr-20200406'},
    {'reference':'texlive-xeindex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xeindex-20180414'},
    {'reference':'texlive-xeindex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xeindex-20200406'},
    {'reference':'texlive-xepersian-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xepersian-20180414'},
    {'reference':'texlive-xepersian-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xepersian-20200406'},
    {'reference':'texlive-xesearch-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xesearch-20180414'},
    {'reference':'texlive-xesearch-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xesearch-20200406'},
    {'reference':'texlive-xetex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-20180414'},
    {'reference':'texlive-xetex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-20180414'},
    {'reference':'texlive-xetex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-20200406'},
    {'reference':'texlive-xetex-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-20200406'},
    {'reference':'texlive-xetex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-20200406'},
    {'reference':'texlive-xetex-debuginfo-20180414-29.el8_8', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-debuginfo-20180414'},
    {'reference':'texlive-xetex-debuginfo-20180414-29.el8_8', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-debuginfo-20180414'},
    {'reference':'texlive-xetex-debuginfo-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-debuginfo-20200406'},
    {'reference':'texlive-xetex-debuginfo-20200406-26.el9_2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-debuginfo-20200406'},
    {'reference':'texlive-xetex-debuginfo-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-debuginfo-20200406'},
    {'reference':'texlive-xetex-itrans-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-itrans-20180414'},
    {'reference':'texlive-xetex-itrans-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-itrans-20200406'},
    {'reference':'texlive-xetex-pstricks-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-pstricks-20180414'},
    {'reference':'texlive-xetex-pstricks-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-pstricks-20200406'},
    {'reference':'texlive-xetex-tibetan-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetex-tibetan-20180414'},
    {'reference':'texlive-xetex-tibetan-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetex-tibetan-20200406'},
    {'reference':'texlive-xetexconfig-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetexconfig-20180414'},
    {'reference':'texlive-xetexconfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetexconfig-20200406'},
    {'reference':'texlive-xetexfontinfo-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xetexfontinfo-20180414'},
    {'reference':'texlive-xetexfontinfo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xetexfontinfo-20200406'},
    {'reference':'texlive-xifthen-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xifthen-20180414'},
    {'reference':'texlive-xifthen-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xifthen-20200406'},
    {'reference':'texlive-xkeyval-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xkeyval-20180414'},
    {'reference':'texlive-xkeyval-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xkeyval-20200406'},
    {'reference':'texlive-xltxtra-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xltxtra-20180414'},
    {'reference':'texlive-xltxtra-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xltxtra-20200406'},
    {'reference':'texlive-xmltex-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xmltex-20180414'},
    {'reference':'texlive-xmltex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xmltex-20200406'},
    {'reference':'texlive-xmltexconfig-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xmltexconfig-20180414'},
    {'reference':'texlive-xmltexconfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xmltexconfig-20200406'},
    {'reference':'texlive-xstring-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xstring-20180414'},
    {'reference':'texlive-xstring-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xstring-20200406'},
    {'reference':'texlive-xtab-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xtab-20180414'},
    {'reference':'texlive-xtab-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xtab-20200406'},
    {'reference':'texlive-xunicode-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-xunicode-20180414'},
    {'reference':'texlive-xunicode-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-xunicode-20200406'},
    {'reference':'texlive-zapfchan-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-zapfchan-20180414'},
    {'reference':'texlive-zapfchan-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-zapfchan-20200406'},
    {'reference':'texlive-zapfding-20180414-29.el8_8', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7', 'exists_check':'texlive-zapfding-20180414'},
    {'reference':'texlive-zapfding-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9', 'exists_check':'texlive-zapfding-20200406'},
    {'reference':'texlive-zref-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'texlive / texlive-adjustbox / texlive-ae / texlive-algorithms / etc');
}
