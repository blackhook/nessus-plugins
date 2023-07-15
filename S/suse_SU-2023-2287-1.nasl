#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2287-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(176355);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id("CVE-2023-24805", "CVE-2023-32700");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2287-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : cups-filters, poppler, texlive (SUSE-SU-2023:2287-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:2287-1 advisory.

  - cups-filters contains backends, filters, and other software required to get the cups printing service
    working on operating systems other than macos. If you use the Backend Error Handler (beh) to create an
    accessible network printer, this security vulnerability can cause remote code execution. `beh.c` contains
    the line `retval = system(cmdline) >> 8;` which calls the `system` command with the operand `cmdline`.
    `cmdline` contains multiple user controlled, unsanitized values. As a result an attacker with network
    access to the hosted print server can exploit this vulnerability to inject system commands which are
    executed in the context of the running server. This issue has been addressed in commit `8f2740357` and is
    expected to be bundled in the next release. Users are advised to upgrade when possible and to restrict
    access to network printers in the meantime. (CVE-2023-24805)

  - LuaTeX before 1.17.0 allows execution of arbitrary shell commands when compiling a TeX file obtained from
    an untrusted source. This occurs because luatex-core.lua lets the original io.popen be accessed. This also
    affects TeX Live before 2023 r66984 and MiKTeX before 23.5. (CVE-2023-32700)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211450");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-May/029509.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-24805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32700");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libkpathsea6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler-cpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpoppler73");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libptexenc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsynctex1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtexlua52-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtexluajit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-biber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-a2ping-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-accfonts-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-adhocfilelist-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-afm2pl-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-aleph-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-amstex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-arara-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-asymptote-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-authorindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-autosp-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-biber-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bibexport-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bibtex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bibtex8-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bibtexu-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bundledoc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cachepic-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-checkcites-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-checklistings-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-chktex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cjk-gs-integrate-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cjkutils-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-context-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-convbkmk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-crossrefware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cslatex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-csplain-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ctanify-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ctanupload-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ctie-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cweb-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cyrillic-bin-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-de-macro-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-detex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-diadia-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dosepsbin-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dtl-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dtxgen-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dviasm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvicopy-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvidvi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dviinfox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dviljk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvipdfmx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvipng-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvipos-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvips-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvisvgm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ebong-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-eplain-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-epspdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-epstopdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-exceltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fig4latex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-findhyph-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fontinst-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fontools-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fontware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fragmaster-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-getmap-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-glossaries-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-gregoriotex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-gsftopk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-jadetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-kotex-utils-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-kpathsea-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-kpathsea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lacheck-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex-bin-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex-git-log-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex-papersize-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex2man-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex2nemeth-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexdiff-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexfileversion-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexindent-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexmk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexpand-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lcdftypetools-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lilyglyphs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-listbib-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-listings-ext-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lollipop-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ltxfileinfo-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ltximg-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lua2dox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-luaotfload-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-luatex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lwarp-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-m-tx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-make4ht-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-makedtx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-makeindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-match_parens-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mathspic-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-metafont-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-metapost-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mf2pt1-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mflua-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mfware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mkgrkindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mkjobtexmf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mkpic-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mptopdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-multibibliography-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-musixtex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-musixtnt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-omegaware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-patgen-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pax-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdfbook2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdfcrop-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdfjam-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdflatexpicscale-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdftex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdftools-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdfxup-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pedigree-perl-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-perltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-petri-nets-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pfarrei-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pkfix-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pkfix-helper-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-platex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pmx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pmxchords-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ps2pk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pst-pdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pst2pdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pstools-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ptex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ptex-fontmaps-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ptex2pdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ptexenc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-purifyeps-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pygmentex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pythontex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-rubik-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-seetexk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-splitindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-srcredact-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-sty2dtx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-svn-multi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-synctex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-synctex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tex4ebook-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tex4ht-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texconfig-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texcount-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texdef-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texdiff-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texdirflatten-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texdoc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texfot-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texliveonfly-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texloganalyser-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texlua-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texluajit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texosquery-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texsis-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-thumbpdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tie-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tpic2pdftex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ttfutils-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-typeoutfileinfo-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ulqda-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-uplatex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-uptex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-urlbst-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-velthuis-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-vlna-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-vpe-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-web-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xdvi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xmltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-yplan-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Poppler-0_18");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cups-filters-1.20.3-150000.3.10.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'cups-filters-devel-1.20.3-150000.3.10.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libkpathsea6-6.2.3-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libpoppler-cpp0-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libpoppler-devel-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libpoppler-glib-devel-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libpoppler-glib8-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libpoppler73-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libptexenc1-1.3.5-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libsynctex1-1.18-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libtexlua52-5-5.2.4-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libtexluajit2-2.1.0beta2-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'perl-biber-2017.20170520.svn30357-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'poppler-tools-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-2017.20170520-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-a2ping-bin-2017.20170520.svn27321-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-accfonts-bin-2017.20170520.svn12688-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-adhocfilelist-bin-2017.20170520.svn28038-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-afm2pl-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-aleph-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-amstex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-arara-bin-2017.20170520.svn29036-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-asymptote-bin-2017.20170520.svn43843-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-authorindex-bin-2017.20170520.svn18790-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-autosp-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-biber-bin-2017.20170520.svn42679-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-bibexport-bin-2017.20170520.svn16219-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-bibtex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-bibtex8-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-bibtexu-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-bin-devel-2017.20170520-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-bundledoc-bin-2017.20170520.svn17794-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-cachepic-bin-2017.20170520.svn15543-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-checkcites-bin-2017.20170520.svn25623-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-checklistings-bin-2017.20170520.svn38300-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-chktex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-cjk-gs-integrate-bin-2017.20170520.svn37223-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-cjkutils-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-context-bin-2017.20170520.svn34112-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-convbkmk-bin-2017.20170520.svn30408-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-crossrefware-bin-2017.20170520.svn43866-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-cslatex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-csplain-bin-2017.20170520.svn33902-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ctanify-bin-2017.20170520.svn24061-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ctanupload-bin-2017.20170520.svn23866-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ctie-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-cweb-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-cyrillic-bin-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-de-macro-bin-2017.20170520.svn17399-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-detex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-diadia-bin-2017.20170520.svn37645-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dosepsbin-bin-2017.20170520.svn24759-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dtl-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dtxgen-bin-2017.20170520.svn29031-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dviasm-bin-2017.20170520.svn8329-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dvicopy-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dvidvi-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dviinfox-bin-2017.20170520.svn44515-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dviljk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dvipdfmx-bin-2017.20170520.svn40273-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dvipng-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dvipos-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dvips-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-dvisvgm-bin-2017.20170520.svn40987-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ebong-bin-2017.20170520.svn21000-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-eplain-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-epspdf-bin-2017.20170520.svn29050-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-epstopdf-bin-2017.20170520.svn18336-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-exceltex-bin-2017.20170520.svn25860-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-fig4latex-bin-2017.20170520.svn14752-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-findhyph-bin-2017.20170520.svn14758-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-fontinst-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-fontools-bin-2017.20170520.svn25997-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-fontware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-fragmaster-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-getmap-bin-2017.20170520.svn34971-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-glossaries-bin-2017.20170520.svn37813-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-gregoriotex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-gsftopk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-jadetex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-kotex-utils-bin-2017.20170520.svn32101-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-kpathsea-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-kpathsea-devel-6.2.3-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-lacheck-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latex-bin-bin-2017.20170520.svn14050-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latex-git-log-bin-2017.20170520.svn30983-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latex-papersize-bin-2017.20170520.svn42296-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latex2man-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latex2nemeth-bin-2017.20170520.svn42300-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latexdiff-bin-2017.20170520.svn16420-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latexfileversion-bin-2017.20170520.svn25012-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latexindent-bin-2017.20170520.svn32150-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latexmk-bin-2017.20170520.svn10937-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-latexpand-bin-2017.20170520.svn27025-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-lcdftypetools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-lilyglyphs-bin-2017.20170520.svn31696-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-listbib-bin-2017.20170520.svn26126-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-listings-ext-bin-2017.20170520.svn15093-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-lollipop-bin-2017.20170520.svn41465-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ltxfileinfo-bin-2017.20170520.svn29005-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ltximg-bin-2017.20170520.svn32346-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-lua2dox-bin-2017.20170520.svn29053-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-luaotfload-bin-2017.20170520.svn34647-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-luatex-bin-2017.20170520.svn44549-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-lwarp-bin-2017.20170520.svn43292-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-m-tx-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-make4ht-bin-2017.20170520.svn37750-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-makedtx-bin-2017.20170520.svn38769-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-makeindex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-match_parens-bin-2017.20170520.svn23500-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mathspic-bin-2017.20170520.svn23661-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-metafont-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-metapost-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mf2pt1-bin-2017.20170520.svn23406-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mflua-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mfware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mkgrkindex-bin-2017.20170520.svn14428-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mkjobtexmf-bin-2017.20170520.svn8457-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mkpic-bin-2017.20170520.svn33688-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mltex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-mptopdf-bin-2017.20170520.svn18674-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-multibibliography-bin-2017.20170520.svn30534-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-musixtex-bin-2017.20170520.svn37026-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-musixtnt-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-omegaware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-patgen-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pax-bin-2017.20170520.svn10843-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pdfbook2-bin-2017.20170520.svn37537-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pdfcrop-bin-2017.20170520.svn14387-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pdfjam-bin-2017.20170520.svn17868-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pdflatexpicscale-bin-2017.20170520.svn41779-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pdftex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pdftools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pdfxup-bin-2017.20170520.svn40690-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pedigree-perl-bin-2017.20170520.svn25962-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-perltex-bin-2017.20170520.svn16181-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-petri-nets-bin-2017.20170520.svn39165-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pfarrei-bin-2017.20170520.svn29348-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pkfix-bin-2017.20170520.svn13364-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pkfix-helper-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-platex-bin-2017.20170520.svn22859-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pmx-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pmxchords-bin-2017.20170520.svn32405-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ps2pk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pst-pdf-bin-2017.20170520.svn7838-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pst2pdf-bin-2017.20170520.svn29333-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pstools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ptex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ptex-fontmaps-bin-2017.20170520.svn44206-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ptex2pdf-bin-2017.20170520.svn29335-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ptexenc-devel-1.3.5-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-purifyeps-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pygmentex-bin-2017.20170520.svn34996-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-pythontex-bin-2017.20170520.svn31638-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-rubik-bin-2017.20170520.svn32919-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-seetexk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-splitindex-bin-2017.20170520.svn29688-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-srcredact-bin-2017.20170520.svn38710-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-sty2dtx-bin-2017.20170520.svn21215-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-svn-multi-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-synctex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-synctex-devel-1.18-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-tetex-bin-2017.20170520.svn43957-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-tex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-tex4ebook-bin-2017.20170520.svn37771-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-tex4ht-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texconfig-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texcount-bin-2017.20170520.svn13013-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texdef-bin-2017.20170520.svn21802-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texdiff-bin-2017.20170520.svn15506-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texdirflatten-bin-2017.20170520.svn12782-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texdoc-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texfot-bin-2017.20170520.svn33155-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texliveonfly-bin-2017.20170520.svn24062-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texloganalyser-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texlua-devel-5.2.4-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texluajit-devel-2.1.0beta2-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texosquery-bin-2017.20170520.svn43596-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texsis-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-texware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-thumbpdf-bin-2017.20170520.svn6898-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-tie-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-tpic2pdftex-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ttfutils-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-typeoutfileinfo-bin-2017.20170520.svn25648-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-ulqda-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-uplatex-bin-2017.20170520.svn26326-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-uptex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-urlbst-bin-2017.20170520.svn23262-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-velthuis-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-vlna-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-vpe-bin-2017.20170520.svn6897-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-web-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-xdvi-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-xetex-bin-2017.20170520.svn44361-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-xmltex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'texlive-yplan-bin-2017.20170520.svn34398-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'typelib-1_0-Poppler-0_18-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'cups-filters-1.20.3-150000.3.10.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'cups-filters-1.20.3-150000.3.10.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'cups-filters-devel-1.20.3-150000.3.10.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'cups-filters-devel-1.20.3-150000.3.10.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libkpathsea6-6.2.3-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libkpathsea6-6.2.3-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler-cpp0-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler-cpp0-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler-devel-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler-devel-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler-glib-devel-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler-glib-devel-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler-glib8-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler-glib8-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler73-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler73-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libptexenc1-1.3.5-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libptexenc1-1.3.5-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libsynctex1-1.18-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libsynctex1-1.18-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libtexlua52-5-5.2.4-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libtexlua52-5-5.2.4-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libtexluajit2-2.1.0beta2-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'libtexluajit2-2.1.0beta2-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'perl-biber-2017.20170520.svn30357-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'poppler-tools-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'poppler-tools-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-2017.20170520-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-2017.20170520-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-a2ping-bin-2017.20170520.svn27321-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-a2ping-bin-2017.20170520.svn27321-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-accfonts-bin-2017.20170520.svn12688-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-accfonts-bin-2017.20170520.svn12688-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-adhocfilelist-bin-2017.20170520.svn28038-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-adhocfilelist-bin-2017.20170520.svn28038-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-afm2pl-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-afm2pl-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-aleph-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-aleph-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-amstex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-amstex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-arara-bin-2017.20170520.svn29036-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-arara-bin-2017.20170520.svn29036-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-asymptote-bin-2017.20170520.svn43843-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-asymptote-bin-2017.20170520.svn43843-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-authorindex-bin-2017.20170520.svn18790-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-authorindex-bin-2017.20170520.svn18790-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-autosp-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-autosp-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-biber-bin-2017.20170520.svn42679-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'texlive-bibexport-bin-2017.20170520.svn16219-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bibexport-bin-2017.20170520.svn16219-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bibtex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bibtex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bibtex8-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bibtex8-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bibtexu-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bibtexu-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bin-devel-2017.20170520-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bin-devel-2017.20170520-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bundledoc-bin-2017.20170520.svn17794-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-bundledoc-bin-2017.20170520.svn17794-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cachepic-bin-2017.20170520.svn15543-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cachepic-bin-2017.20170520.svn15543-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-checkcites-bin-2017.20170520.svn25623-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-checkcites-bin-2017.20170520.svn25623-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-checklistings-bin-2017.20170520.svn38300-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-checklistings-bin-2017.20170520.svn38300-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-chktex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-chktex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cjk-gs-integrate-bin-2017.20170520.svn37223-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cjk-gs-integrate-bin-2017.20170520.svn37223-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cjkutils-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cjkutils-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-context-bin-2017.20170520.svn34112-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-context-bin-2017.20170520.svn34112-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-convbkmk-bin-2017.20170520.svn30408-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-convbkmk-bin-2017.20170520.svn30408-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-crossrefware-bin-2017.20170520.svn43866-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-crossrefware-bin-2017.20170520.svn43866-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cslatex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cslatex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-csplain-bin-2017.20170520.svn33902-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-csplain-bin-2017.20170520.svn33902-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ctanify-bin-2017.20170520.svn24061-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ctanify-bin-2017.20170520.svn24061-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ctanupload-bin-2017.20170520.svn23866-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ctanupload-bin-2017.20170520.svn23866-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ctie-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ctie-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cweb-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cweb-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cyrillic-bin-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-cyrillic-bin-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-de-macro-bin-2017.20170520.svn17399-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-de-macro-bin-2017.20170520.svn17399-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-detex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-detex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-diadia-bin-2017.20170520.svn37645-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'texlive-dosepsbin-bin-2017.20170520.svn24759-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dosepsbin-bin-2017.20170520.svn24759-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dtl-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dtl-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dtxgen-bin-2017.20170520.svn29031-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dtxgen-bin-2017.20170520.svn29031-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dviasm-bin-2017.20170520.svn8329-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dviasm-bin-2017.20170520.svn8329-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvicopy-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvicopy-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvidvi-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvidvi-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dviinfox-bin-2017.20170520.svn44515-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dviinfox-bin-2017.20170520.svn44515-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dviljk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dviljk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvipdfmx-bin-2017.20170520.svn40273-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvipdfmx-bin-2017.20170520.svn40273-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvipng-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvipng-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvipos-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvipos-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvips-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvips-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvisvgm-bin-2017.20170520.svn40987-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-dvisvgm-bin-2017.20170520.svn40987-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ebong-bin-2017.20170520.svn21000-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ebong-bin-2017.20170520.svn21000-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-eplain-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-eplain-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-epspdf-bin-2017.20170520.svn29050-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-epspdf-bin-2017.20170520.svn29050-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-epstopdf-bin-2017.20170520.svn18336-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-epstopdf-bin-2017.20170520.svn18336-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-exceltex-bin-2017.20170520.svn25860-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-exceltex-bin-2017.20170520.svn25860-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fig4latex-bin-2017.20170520.svn14752-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fig4latex-bin-2017.20170520.svn14752-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-findhyph-bin-2017.20170520.svn14758-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-findhyph-bin-2017.20170520.svn14758-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fontinst-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fontinst-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fontools-bin-2017.20170520.svn25997-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fontools-bin-2017.20170520.svn25997-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fontware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fontware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fragmaster-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-fragmaster-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-getmap-bin-2017.20170520.svn34971-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-getmap-bin-2017.20170520.svn34971-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-glossaries-bin-2017.20170520.svn37813-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-glossaries-bin-2017.20170520.svn37813-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-gregoriotex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-gregoriotex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-gsftopk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-gsftopk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-jadetex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-jadetex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-kotex-utils-bin-2017.20170520.svn32101-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-kotex-utils-bin-2017.20170520.svn32101-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-kpathsea-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-kpathsea-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-kpathsea-devel-6.2.3-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-kpathsea-devel-6.2.3-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lacheck-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lacheck-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex-bin-bin-2017.20170520.svn14050-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex-bin-bin-2017.20170520.svn14050-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex-git-log-bin-2017.20170520.svn30983-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex-git-log-bin-2017.20170520.svn30983-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex-papersize-bin-2017.20170520.svn42296-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex-papersize-bin-2017.20170520.svn42296-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex2man-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex2man-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex2nemeth-bin-2017.20170520.svn42300-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latex2nemeth-bin-2017.20170520.svn42300-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexdiff-bin-2017.20170520.svn16420-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexdiff-bin-2017.20170520.svn16420-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexfileversion-bin-2017.20170520.svn25012-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexfileversion-bin-2017.20170520.svn25012-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexindent-bin-2017.20170520.svn32150-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexindent-bin-2017.20170520.svn32150-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexmk-bin-2017.20170520.svn10937-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexmk-bin-2017.20170520.svn10937-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexpand-bin-2017.20170520.svn27025-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-latexpand-bin-2017.20170520.svn27025-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lcdftypetools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lcdftypetools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lilyglyphs-bin-2017.20170520.svn31696-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lilyglyphs-bin-2017.20170520.svn31696-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-listbib-bin-2017.20170520.svn26126-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-listbib-bin-2017.20170520.svn26126-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-listings-ext-bin-2017.20170520.svn15093-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-listings-ext-bin-2017.20170520.svn15093-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lollipop-bin-2017.20170520.svn41465-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lollipop-bin-2017.20170520.svn41465-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ltxfileinfo-bin-2017.20170520.svn29005-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ltxfileinfo-bin-2017.20170520.svn29005-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ltximg-bin-2017.20170520.svn32346-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ltximg-bin-2017.20170520.svn32346-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lua2dox-bin-2017.20170520.svn29053-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lua2dox-bin-2017.20170520.svn29053-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-luaotfload-bin-2017.20170520.svn34647-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-luaotfload-bin-2017.20170520.svn34647-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-luatex-bin-2017.20170520.svn44549-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-luatex-bin-2017.20170520.svn44549-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lwarp-bin-2017.20170520.svn43292-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-lwarp-bin-2017.20170520.svn43292-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-m-tx-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-m-tx-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-make4ht-bin-2017.20170520.svn37750-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-make4ht-bin-2017.20170520.svn37750-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-makedtx-bin-2017.20170520.svn38769-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-makedtx-bin-2017.20170520.svn38769-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-makeindex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-makeindex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-match_parens-bin-2017.20170520.svn23500-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-match_parens-bin-2017.20170520.svn23500-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mathspic-bin-2017.20170520.svn23661-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mathspic-bin-2017.20170520.svn23661-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-metafont-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-metafont-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-metapost-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-metapost-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mf2pt1-bin-2017.20170520.svn23406-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mf2pt1-bin-2017.20170520.svn23406-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mflua-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mflua-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mfware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mfware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mkgrkindex-bin-2017.20170520.svn14428-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mkgrkindex-bin-2017.20170520.svn14428-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mkjobtexmf-bin-2017.20170520.svn8457-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mkjobtexmf-bin-2017.20170520.svn8457-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mkpic-bin-2017.20170520.svn33688-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mkpic-bin-2017.20170520.svn33688-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mltex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mltex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mptopdf-bin-2017.20170520.svn18674-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-mptopdf-bin-2017.20170520.svn18674-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-multibibliography-bin-2017.20170520.svn30534-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-multibibliography-bin-2017.20170520.svn30534-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-musixtex-bin-2017.20170520.svn37026-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-musixtex-bin-2017.20170520.svn37026-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-musixtnt-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-musixtnt-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-omegaware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-omegaware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-patgen-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-patgen-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pax-bin-2017.20170520.svn10843-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pax-bin-2017.20170520.svn10843-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdfbook2-bin-2017.20170520.svn37537-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdfbook2-bin-2017.20170520.svn37537-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdfcrop-bin-2017.20170520.svn14387-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdfcrop-bin-2017.20170520.svn14387-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdfjam-bin-2017.20170520.svn17868-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdfjam-bin-2017.20170520.svn17868-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdflatexpicscale-bin-2017.20170520.svn41779-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdflatexpicscale-bin-2017.20170520.svn41779-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdftex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdftex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdftools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdftools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdfxup-bin-2017.20170520.svn40690-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pdfxup-bin-2017.20170520.svn40690-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pedigree-perl-bin-2017.20170520.svn25962-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pedigree-perl-bin-2017.20170520.svn25962-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-perltex-bin-2017.20170520.svn16181-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-perltex-bin-2017.20170520.svn16181-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-petri-nets-bin-2017.20170520.svn39165-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-petri-nets-bin-2017.20170520.svn39165-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pfarrei-bin-2017.20170520.svn29348-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pfarrei-bin-2017.20170520.svn29348-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pkfix-bin-2017.20170520.svn13364-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pkfix-bin-2017.20170520.svn13364-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pkfix-helper-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pkfix-helper-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-platex-bin-2017.20170520.svn22859-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-platex-bin-2017.20170520.svn22859-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pmx-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pmx-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pmxchords-bin-2017.20170520.svn32405-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pmxchords-bin-2017.20170520.svn32405-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ps2pk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ps2pk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pst-pdf-bin-2017.20170520.svn7838-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pst-pdf-bin-2017.20170520.svn7838-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pst2pdf-bin-2017.20170520.svn29333-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pst2pdf-bin-2017.20170520.svn29333-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pstools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pstools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ptex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ptex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ptex-fontmaps-bin-2017.20170520.svn44206-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ptex-fontmaps-bin-2017.20170520.svn44206-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ptex2pdf-bin-2017.20170520.svn29335-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ptex2pdf-bin-2017.20170520.svn29335-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ptexenc-devel-1.3.5-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ptexenc-devel-1.3.5-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-purifyeps-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-purifyeps-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pygmentex-bin-2017.20170520.svn34996-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pygmentex-bin-2017.20170520.svn34996-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pythontex-bin-2017.20170520.svn31638-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-pythontex-bin-2017.20170520.svn31638-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-rubik-bin-2017.20170520.svn32919-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-rubik-bin-2017.20170520.svn32919-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-seetexk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-seetexk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-splitindex-bin-2017.20170520.svn29688-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-splitindex-bin-2017.20170520.svn29688-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-srcredact-bin-2017.20170520.svn38710-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-srcredact-bin-2017.20170520.svn38710-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-sty2dtx-bin-2017.20170520.svn21215-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-sty2dtx-bin-2017.20170520.svn21215-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-svn-multi-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-svn-multi-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-synctex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-synctex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-synctex-devel-1.18-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-synctex-devel-1.18-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tetex-bin-2017.20170520.svn43957-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tetex-bin-2017.20170520.svn43957-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tex4ebook-bin-2017.20170520.svn37771-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tex4ebook-bin-2017.20170520.svn37771-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tex4ht-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tex4ht-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texconfig-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texconfig-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texcount-bin-2017.20170520.svn13013-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texcount-bin-2017.20170520.svn13013-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texdef-bin-2017.20170520.svn21802-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texdef-bin-2017.20170520.svn21802-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texdiff-bin-2017.20170520.svn15506-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texdiff-bin-2017.20170520.svn15506-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texdirflatten-bin-2017.20170520.svn12782-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texdirflatten-bin-2017.20170520.svn12782-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texdoc-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texdoc-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texfot-bin-2017.20170520.svn33155-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texfot-bin-2017.20170520.svn33155-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texliveonfly-bin-2017.20170520.svn24062-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texliveonfly-bin-2017.20170520.svn24062-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texloganalyser-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texloganalyser-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texlua-devel-5.2.4-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texlua-devel-5.2.4-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texluajit-devel-2.1.0beta2-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'texlive-texluajit-devel-2.1.0beta2-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'texlive-texosquery-bin-2017.20170520.svn43596-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texosquery-bin-2017.20170520.svn43596-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texsis-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texsis-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-texware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-thumbpdf-bin-2017.20170520.svn6898-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-thumbpdf-bin-2017.20170520.svn6898-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tie-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tie-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tpic2pdftex-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-tpic2pdftex-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ttfutils-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ttfutils-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-typeoutfileinfo-bin-2017.20170520.svn25648-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-typeoutfileinfo-bin-2017.20170520.svn25648-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ulqda-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-ulqda-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-uplatex-bin-2017.20170520.svn26326-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-uplatex-bin-2017.20170520.svn26326-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-uptex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-uptex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-urlbst-bin-2017.20170520.svn23262-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-urlbst-bin-2017.20170520.svn23262-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-velthuis-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-velthuis-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-vlna-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-vlna-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-vpe-bin-2017.20170520.svn6897-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-vpe-bin-2017.20170520.svn6897-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-web-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-web-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-xdvi-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-xdvi-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-xetex-bin-2017.20170520.svn44361-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-xetex-bin-2017.20170520.svn44361-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-xmltex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-xmltex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-yplan-bin-2017.20170520.svn34398-150000.11.20.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'texlive-yplan-bin-2017.20170520.svn34398-150000.11.20.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'typelib-1_0-Poppler-0_18-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'typelib-1_0-Poppler-0_18-0.62.0-150000.4.12.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'libpoppler73-0.62.0-150000.4.12.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libpoppler73-32bit-0.62.0-150000.4.12.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'cups-filters-1.20.3-150000.3.10.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'cups-filters-devel-1.20.3-150000.3.10.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libkpathsea6-6.2.3-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libpoppler-cpp0-0.62.0-150000.4.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libpoppler-devel-0.62.0-150000.4.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libpoppler-glib-devel-0.62.0-150000.4.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libpoppler-glib8-0.62.0-150000.4.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libpoppler73-0.62.0-150000.4.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libptexenc1-1.3.5-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libsynctex1-1.18-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libtexlua52-5-5.2.4-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'poppler-tools-0.62.0-150000.4.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-2017.20170520-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-a2ping-bin-2017.20170520.svn27321-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-accfonts-bin-2017.20170520.svn12688-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-adhocfilelist-bin-2017.20170520.svn28038-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-afm2pl-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-aleph-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-amstex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-arara-bin-2017.20170520.svn29036-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-asymptote-bin-2017.20170520.svn43843-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-authorindex-bin-2017.20170520.svn18790-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-autosp-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-bibexport-bin-2017.20170520.svn16219-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-bibtex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-bibtex8-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-bibtexu-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-bin-devel-2017.20170520-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-bundledoc-bin-2017.20170520.svn17794-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-cachepic-bin-2017.20170520.svn15543-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-checkcites-bin-2017.20170520.svn25623-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-checklistings-bin-2017.20170520.svn38300-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-chktex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-cjk-gs-integrate-bin-2017.20170520.svn37223-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-cjkutils-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-context-bin-2017.20170520.svn34112-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-convbkmk-bin-2017.20170520.svn30408-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-crossrefware-bin-2017.20170520.svn43866-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-cslatex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-csplain-bin-2017.20170520.svn33902-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ctanify-bin-2017.20170520.svn24061-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ctanupload-bin-2017.20170520.svn23866-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ctie-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-cweb-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-cyrillic-bin-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-de-macro-bin-2017.20170520.svn17399-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-detex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dosepsbin-bin-2017.20170520.svn24759-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dtl-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dtxgen-bin-2017.20170520.svn29031-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dviasm-bin-2017.20170520.svn8329-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dvicopy-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dvidvi-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dviinfox-bin-2017.20170520.svn44515-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dviljk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dvipdfmx-bin-2017.20170520.svn40273-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dvipng-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dvipos-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dvips-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-dvisvgm-bin-2017.20170520.svn40987-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ebong-bin-2017.20170520.svn21000-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-eplain-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-epspdf-bin-2017.20170520.svn29050-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-epstopdf-bin-2017.20170520.svn18336-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-exceltex-bin-2017.20170520.svn25860-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-fig4latex-bin-2017.20170520.svn14752-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-findhyph-bin-2017.20170520.svn14758-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-fontinst-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-fontools-bin-2017.20170520.svn25997-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-fontware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-fragmaster-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-getmap-bin-2017.20170520.svn34971-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-glossaries-bin-2017.20170520.svn37813-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-gregoriotex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-gsftopk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-jadetex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-kotex-utils-bin-2017.20170520.svn32101-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-kpathsea-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-kpathsea-devel-6.2.3-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-lacheck-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latex-bin-bin-2017.20170520.svn14050-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latex-git-log-bin-2017.20170520.svn30983-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latex-papersize-bin-2017.20170520.svn42296-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latex2man-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latex2nemeth-bin-2017.20170520.svn42300-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latexdiff-bin-2017.20170520.svn16420-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latexfileversion-bin-2017.20170520.svn25012-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latexindent-bin-2017.20170520.svn32150-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latexmk-bin-2017.20170520.svn10937-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-latexpand-bin-2017.20170520.svn27025-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-lcdftypetools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-lilyglyphs-bin-2017.20170520.svn31696-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-listbib-bin-2017.20170520.svn26126-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-listings-ext-bin-2017.20170520.svn15093-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-lollipop-bin-2017.20170520.svn41465-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ltxfileinfo-bin-2017.20170520.svn29005-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ltximg-bin-2017.20170520.svn32346-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-lua2dox-bin-2017.20170520.svn29053-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-luaotfload-bin-2017.20170520.svn34647-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-luatex-bin-2017.20170520.svn44549-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-lwarp-bin-2017.20170520.svn43292-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-m-tx-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-make4ht-bin-2017.20170520.svn37750-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-makedtx-bin-2017.20170520.svn38769-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-makeindex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-match_parens-bin-2017.20170520.svn23500-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mathspic-bin-2017.20170520.svn23661-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-metafont-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-metapost-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mf2pt1-bin-2017.20170520.svn23406-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mflua-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mfware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mkgrkindex-bin-2017.20170520.svn14428-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mkjobtexmf-bin-2017.20170520.svn8457-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mkpic-bin-2017.20170520.svn33688-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mltex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-mptopdf-bin-2017.20170520.svn18674-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-multibibliography-bin-2017.20170520.svn30534-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-musixtex-bin-2017.20170520.svn37026-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-musixtnt-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-omegaware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-patgen-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pax-bin-2017.20170520.svn10843-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pdfbook2-bin-2017.20170520.svn37537-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pdfcrop-bin-2017.20170520.svn14387-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pdfjam-bin-2017.20170520.svn17868-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pdflatexpicscale-bin-2017.20170520.svn41779-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pdftex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pdftools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pdfxup-bin-2017.20170520.svn40690-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pedigree-perl-bin-2017.20170520.svn25962-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-perltex-bin-2017.20170520.svn16181-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-petri-nets-bin-2017.20170520.svn39165-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pfarrei-bin-2017.20170520.svn29348-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pkfix-bin-2017.20170520.svn13364-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pkfix-helper-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-platex-bin-2017.20170520.svn22859-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pmx-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pmxchords-bin-2017.20170520.svn32405-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ps2pk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pst-pdf-bin-2017.20170520.svn7838-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pst2pdf-bin-2017.20170520.svn29333-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pstools-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ptex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ptex-fontmaps-bin-2017.20170520.svn44206-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ptex2pdf-bin-2017.20170520.svn29335-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ptexenc-devel-1.3.5-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-purifyeps-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pygmentex-bin-2017.20170520.svn34996-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-pythontex-bin-2017.20170520.svn31638-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-rubik-bin-2017.20170520.svn32919-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-seetexk-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-splitindex-bin-2017.20170520.svn29688-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-srcredact-bin-2017.20170520.svn38710-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-sty2dtx-bin-2017.20170520.svn21215-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-svn-multi-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-synctex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-synctex-devel-1.18-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-tetex-bin-2017.20170520.svn43957-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-tex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-tex4ebook-bin-2017.20170520.svn37771-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-tex4ht-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texconfig-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texcount-bin-2017.20170520.svn13013-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texdef-bin-2017.20170520.svn21802-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texdiff-bin-2017.20170520.svn15506-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texdirflatten-bin-2017.20170520.svn12782-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texdoc-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texfot-bin-2017.20170520.svn33155-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texliveonfly-bin-2017.20170520.svn24062-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texloganalyser-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texlua-devel-5.2.4-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texosquery-bin-2017.20170520.svn43596-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texsis-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-texware-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-thumbpdf-bin-2017.20170520.svn6898-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-tie-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-tpic2pdftex-bin-2017.20170520.svn29741-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ttfutils-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-typeoutfileinfo-bin-2017.20170520.svn25648-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-ulqda-bin-2017.20170520.svn13663-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-uplatex-bin-2017.20170520.svn26326-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-uptex-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-urlbst-bin-2017.20170520.svn23262-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-velthuis-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-vlna-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-vpe-bin-2017.20170520.svn6897-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-web-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-xdvi-bin-2017.20170520.svn44143-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-xetex-bin-2017.20170520.svn44361-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-xmltex-bin-2017.20170520.svn3006-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'texlive-yplan-bin-2017.20170520.svn34398-150000.11.20.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'typelib-1_0-Poppler-0_18-0.62.0-150000.4.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cups-filters / cups-filters-devel / libkpathsea6 / libpoppler-cpp0 / etc');
}
