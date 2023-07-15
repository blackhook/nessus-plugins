#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-3661.
##

include('compat.inc');

if (description)
{
  script_id(177521);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id("CVE-2023-32700");

  script_name(english:"Oracle Linux 8 / 9 : texlive (ELSA-2023-3661)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 / 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2023-3661 advisory.

  - LuaTeX before 1.17.0 allows execution of arbitrary shell commands when compiling a TeX file obtained from
    an untrusted source. This occurs because luatex-core.lua lets the original io.popen be accessed. This also
    affects TeX Live before 2023 r66984 and MiKTeX before 23.5. (CVE-2023-32700)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-3661.html");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-adjustbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-algorithms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-alphalph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-amscls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-amsfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-amsmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-anyfontsize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-anysize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-appendix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-arabxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-arphic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-atbegshi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-attachfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-attachfile2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-atveryend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-auxhook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-avantgar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-awesomebox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-babel-english");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-babelbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-beamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-bera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-beton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-bibtex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-bibtopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-bidi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-bigfoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-bigintcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-bitset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-bookman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-bookmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-booktabs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-breakurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-breqn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-capt-of");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-caption");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-carlisle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-catchfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-changebar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-changepage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-charter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-chngcntr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-cite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-cjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-classpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-cm-lgc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-cm-super");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-cmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-cmextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-cns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-collectbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-collection-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-collection-fontsrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-collection-htmlxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-collection-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-collection-latexrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-collection-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-colorprofiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-colortbl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-courier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-crop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-csquotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ctable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ctablestack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-currfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-datetime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-dehyph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-dvipdfmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-dvipng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-dvisvgm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-eepic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-enctex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-enumitem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-environ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-epsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-epstopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-epstopdf-pkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-eqparbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-eso-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-etex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-etex-pkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-etexcmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-etoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-etoolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-euenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-euler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-euro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-eurosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-extsizes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fancybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fancyhdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fancyref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fancyvrb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-filecontents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-filehook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-finstrut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fix2col");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fixlatvian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-float");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fmtcount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fncychap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fontawesome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fontbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fonts-tlwg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fontspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fontware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fontwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-footmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-footnotehyper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-fpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-framed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-garuda-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-geometry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-gettitlestring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-glyphlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-gnu-freefont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-graphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-graphics-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-graphics-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-grfext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-grffile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-gsftopk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-hanging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-helvetic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-hobsub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-hologo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-hycolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-hyperref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-hyph-utf8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-hyphen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-hyphenat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-hyphenex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ifetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ifluatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ifmtarg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ifoddpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ifplatform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-iftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ifxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-index");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-infwarerr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-intcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-jknapltx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-kastrup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-kerkis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-knuth-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-knuth-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-koma-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-kvdefinekeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-kvoptions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-kvsetkeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-l3backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-l3experimental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-l3kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-l3packages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lastpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-latex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-latex2man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-latexbug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-latexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-letltxmacro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lettrine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-linegoal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lineno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-listings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-listofitems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lm-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ltabptch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ltxcmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ltxmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lua-alt-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-luahbtex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lualatex-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lualibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-luaotfload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-luatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-luatex85");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-luatexbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-lwarp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-makecmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-makeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-manfnt-font");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-marginnote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-marvosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mathpazo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mathspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mathtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mdwtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-memoir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-metafont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-metalogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mflogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mflogo-font");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mfnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mfware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-microtype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-minitoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mnsymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-modes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mparhack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-mptopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-multido");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-multirow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-natbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ncctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ncntrsbk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-needspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-newfloat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-newunicodechar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-norasi-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-notoccite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ntgclass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-oberdiek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-overpic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-palatino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-paralist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-parallel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-parskip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-passivetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pdfcolmk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pdfescape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pdflscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pdfpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pdftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pdftexcmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pgf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-philokalia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-placeins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-polyglossia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-powerdot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-preprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-psfrag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pslatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-psnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pspicture");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-arrow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-blur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-coil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-fill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-grad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-plot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-slpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pst-tree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pstricks-add");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ptext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-pxfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-qstest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ragged2e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-rcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-realscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-refcount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-rerunfilecheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-rsfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-sansmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-sansmathaccent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-sauerj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-scheme-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-section");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-sectsty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-seminar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-sepnum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-setspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-showexpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-soul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-stackengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-stmaryrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-stringenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-subfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-subfigure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-svn-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-t2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tabu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tabulary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tex-gyre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tex-gyre-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tex-ini-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tex4ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-texconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-texlive-common-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-texlive-docindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-texlive-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-texlive-msg-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-texlive-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-texlive-scripts-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-texlive.infra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-textcase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-textpos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-threeparttable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-thumbpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-times");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-titlesec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-titling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tocloft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-translator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-trimspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-txfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-type1cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-typehtml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ucharcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ucharclasses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-uhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-ulem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-underscore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-unicode-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-unicode-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-uniquecounter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-unisugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-updmap-map");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-upquote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-utopia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-varwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-wadalab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-was");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-wasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-wasy-type1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-wasy2-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-wasysym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-wrapfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xcolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xecjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xecolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xecyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xepersian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xesearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xetex-itrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xetex-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xetex-tibetan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xetexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xetexfontinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xifthen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xkeyval");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xltxtra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xmltex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xmltexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xtab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-xunicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-zapfchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-zapfding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:texlive-zref");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^(8|9)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8 / 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'texlive-adjustbox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ae-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-algorithms-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-amscls-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-amsfonts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-amsmath-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-anyfontsize-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-anysize-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-appendix-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-arabxetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-arphic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-attachfile-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-avantgar-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-awesomebox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-babel-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-babel-english-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-babelbib-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-base-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-beamer-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bera-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-beton-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bibtopic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bidi-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bigfoot-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bookman-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-booktabs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-breakurl-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-breqn-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-capt-of-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-caption-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-carlisle-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-changebar-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-changepage-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-charter-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-chngcntr-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cite-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cjk-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-classpack-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cm-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cm-lgc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cm-super-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cmap-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cmextra-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cns-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collectbox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-basic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-fontsrecommended-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-htmlxml-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-latex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-latexrecommended-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-xetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-colortbl-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-context-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-courier-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-crop-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-csquotes-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ctable-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ctablestack-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-currfile-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-datetime-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ec-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eepic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-enctex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-enumitem-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-environ-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-epsf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-epstopdf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eqparbox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eso-pic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-etex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-etex-pkg-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-etoolbox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-euenc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-euler-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-euro-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eurosym-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-extsizes-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancybox-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancyhdr-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancyref-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancyvrb-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-filecontents-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-filehook-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-finstrut-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fix2col-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fixlatvian-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-float-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fmtcount-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fncychap-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontawesome-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontbook-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fonts-tlwg-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontspec-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontwrap-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-footmisc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fp-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fpl-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-framed-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-garuda-c90-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-geometry-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-glyphlist-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-graphics-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-graphics-cfg-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-graphics-def-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-helvetic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyperref-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyph-utf8-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyphen-base-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyphenat-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifluatex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifmtarg-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifoddpage-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-iftex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifxetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-import-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-index-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-jadetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-jknapltx-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kastrup-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kerkis-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-knuth-lib-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-knuth-local-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-koma-script-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-l3experimental-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-l3kernel-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-l3packages-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lastpage-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latex-fonts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latex2man-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latexconfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lettrine-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-linegoal-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lineno-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-listings-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lm-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lm-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ltabptch-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ltxmisc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lua-alt-getopt-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lualatex-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lualibs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luaotfload-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatex85-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatexbase-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-makecmds-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-manfnt-font-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-marginnote-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-marvosym-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mathpazo-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mathspec-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mathtools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mdwtools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-memoir-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metalogo-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mflogo-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mflogo-font-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mfnfss-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-microtype-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mnsymbol-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mparhack-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mptopdf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ms-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-multido-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-multirow-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-natbib-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ncctools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ncntrsbk-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-needspace-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-norasi-c90-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ntgclass-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-oberdiek-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-overpic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-palatino-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-paralist-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-parallel-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-parskip-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-passivetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pdfpages-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pgf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-philokalia-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-placeins-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-plain-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-polyglossia-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-powerdot-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-preprint-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-psfrag-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pslatex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-psnfss-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pspicture-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-3d-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-arrow-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-blur-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-coil-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-eps-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-fill-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-grad-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-node-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-plot-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-slpe-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-text-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-tools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-tree-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pstricks-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pstricks-add-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ptext-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pxfonts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-qstest-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-rcs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-realscripts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-rsfs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sansmath-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sauerj-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-scheme-basic-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-section-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sectsty-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-seminar-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sepnum-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-setspace-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-showexpl-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-soul-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-stmaryrd-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-subfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-subfigure-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-svn-prov-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-symbol-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-t2-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tabu-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tabulary-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tetex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-gyre-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-gyre-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-ini-files-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texconfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-common-doc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-docindex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-en-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-msg-translations-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-scripts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive.infra-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-textcase-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-textpos-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-threeparttable-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-thumbpdf-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-times-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tipa-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-titlesec-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-titling-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tocloft-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tools-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-translator-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-trimspaces-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-txfonts-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-type1cm-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-typehtml-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ucharclasses-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ucs-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-uhc-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ulem-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-underscore-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-unicode-data-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-unicode-math-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-unisugar-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-updmap-map-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-upquote-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-url-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-utopia-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-varwidth-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wadalab-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-was-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasy-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasy2-ps-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasysym-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wrapfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xcolor-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xecjk-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xecolor-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xecyr-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xeindex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xepersian-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xesearch-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-itrans-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-pstricks-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-tibetan-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetexconfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetexfontinfo-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xifthen-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xkeyval-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xltxtra-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xmltex-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xmltexconfig-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xstring-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xtab-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xunicode-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-zapfchan-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-zapfding-20180414-29.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bibtex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvipdfmx-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvipng-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvips-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvisvgm-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontware-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-gsftopk-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kpathsea-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-devel-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-makeindex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metafont-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metapost-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mfware-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pdftex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex4ht-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xdvi-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-20180414-29.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-20180414-29.el8_8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-devel-20180414-29.el8_8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bibtex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvipdfmx-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvipng-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvips-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvisvgm-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontware-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-gsftopk-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kpathsea-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-devel-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-makeindex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metafont-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metapost-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mfware-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pdftex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex4ht-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xdvi-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-20180414-29.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-adjustbox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ae-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-algorithms-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-alphalph-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-amscls-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-amsfonts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-amsmath-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-anyfontsize-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-anysize-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-appendix-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-arabxetex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-arphic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-atbegshi-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-attachfile-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-attachfile2-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-atveryend-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-auxhook-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-avantgar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-awesomebox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-babel-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-babel-english-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-babelbib-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-base-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-beamer-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bera-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-beton-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bibtopic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bidi-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bigfoot-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bigintcalc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bitset-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bookman-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bookmark-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-booktabs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-breakurl-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-breqn-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-capt-of-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-caption-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-carlisle-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-catchfile-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-changebar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-changepage-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-charter-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-chngcntr-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cite-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cjk-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-classpack-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cm-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cm-lgc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cm-super-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cmap-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cmextra-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cns-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collectbox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-basic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-fontsrecommended-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-htmlxml-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-latex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-latexrecommended-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-xetex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-colorprofiles-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-colortbl-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-context-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-courier-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-crop-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-csquotes-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ctable-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ctablestack-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-currfile-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-datetime-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dehyph-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ec-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eepic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-enctex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-enumitem-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-environ-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-epsf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-epstopdf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-epstopdf-pkg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eqparbox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eso-pic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etex-pkg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etexcmds-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etoc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etoolbox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-euenc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-euler-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-euro-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eurosym-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-extsizes-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fancybox-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fancyhdr-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fancyref-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fancyvrb-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-filecontents-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-filehook-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-finstrut-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fix2col-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fixlatvian-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-float-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fmtcount-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fncychap-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontawesome-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontbook-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fonts-tlwg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontspec-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontwrap-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-footmisc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-footnotehyper-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fp-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fpl-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-framed-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-garuda-c90-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-geometry-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-gettitlestring-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-glyphlist-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-gnu-freefont-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-graphics-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-graphics-cfg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-graphics-def-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-grfext-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-grffile-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hanging-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-helvetic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hobsub-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hologo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hycolor-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyperref-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyph-utf8-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyphen-base-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyphenat-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyphenex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ifmtarg-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ifoddpage-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ifplatform-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-iftex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-import-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-index-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-infwarerr-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-intcalc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-jadetex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-jknapltx-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kastrup-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kerkis-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-knuth-lib-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-knuth-local-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-koma-script-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvdefinekeys-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvoptions-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvsetkeys-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3backend-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3experimental-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3kernel-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3packages-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lastpage-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latex-fonts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latex2man-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latexbug-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latexconfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-letltxmacro-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lettrine-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-linegoal-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lineno-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-listings-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-listofitems-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lm-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lm-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ltabptch-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ltxcmds-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ltxmisc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lua-alt-getopt-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lualatex-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lualibs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luaotfload-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luatex85-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luatexbase-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lwarp-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-makecmds-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-manfnt-font-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-marginnote-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-marvosym-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mathpazo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mathspec-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mathtools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mdwtools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-memoir-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-metalogo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mflogo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mflogo-font-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mfnfss-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-microtype-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-minitoc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mnsymbol-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-modes-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mparhack-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mptopdf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ms-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-multido-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-multirow-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-natbib-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ncctools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ncntrsbk-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-needspace-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-newfloat-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-newunicodechar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-norasi-c90-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-notoccite-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ntgclass-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-oberdiek-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-obsolete-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-overpic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-palatino-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-paralist-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-parallel-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-parskip-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-passivetex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfcolmk-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfescape-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdflscape-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfpages-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdftexcmds-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pgf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-philokalia-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-placeins-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-plain-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-polyglossia-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-powerdot-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-preprint-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-psfrag-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pslatex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-psnfss-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pspicture-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-3d-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-arrow-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-blur-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-coil-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-eps-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-fill-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-grad-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-node-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-plot-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-slpe-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-text-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-tools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-tree-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pstricks-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pstricks-add-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ptext-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pxfonts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-qstest-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ragged2e-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rcs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-realscripts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-refcount-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rerunfilecheck-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rsfs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sansmath-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sansmathaccent-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sauerj-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-scheme-basic-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-section-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sectsty-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-seminar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sepnum-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-setspace-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-showexpl-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-soul-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-stackengine-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-stmaryrd-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-stringenc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-subfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-subfigure-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-svn-prov-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-symbol-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-t2-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tabu-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tabulary-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex-gyre-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex-gyre-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex-ini-files-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-common-doc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-docindex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-en-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-msg-translations-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-scripts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-scripts-extra-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive.infra-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-textcase-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-textpos-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-threeparttable-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-thumbpdf-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-times-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tipa-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-titlesec-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-titling-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tocloft-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tools-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-translator-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-trimspaces-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-txfonts-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-type1cm-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-typehtml-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ucharcat-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ucharclasses-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ucs-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-uhc-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ulem-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-underscore-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-unicode-data-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-unicode-math-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-uniquecounter-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-unisugar-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-updmap-map-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-upquote-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-url-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-utopia-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-varwidth-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wadalab-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-was-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wasy-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wasy-type1-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wasysym-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wrapfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xcolor-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xecjk-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xecolor-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xecyr-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xeindex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xepersian-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xesearch-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetex-itrans-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetex-pstricks-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetex-tibetan-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetexconfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetexfontinfo-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xifthen-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xkeyval-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xltxtra-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xmltex-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xmltexconfig-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xstring-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xtab-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xunicode-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-zapfchan-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-zapfding-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-zref-20200406-26.el9_2', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bibtex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvipdfmx-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvipng-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvips-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvisvgm-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontware-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-gsftopk-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kpathsea-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luatex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-makeindex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-metafont-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-metapost-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mfware-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdftex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex4ht-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xdvi-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetex-20200406-26.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bibtex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvipdfmx-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvipng-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvips-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvisvgm-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontware-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-gsftopk-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kpathsea-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lib-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lib-devel-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luatex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-makeindex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-metafont-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-metapost-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mfware-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdftex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex4ht-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xdvi-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetex-20200406-26.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'texlive / texlive-adjustbox / texlive-ae / etc');
}
