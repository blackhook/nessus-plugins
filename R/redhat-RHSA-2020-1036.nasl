##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1036. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(136321);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2018-17407");
  script_bugtraq_id(107220);
  script_xref(name:"RHSA", value:"2020:1036");

  script_name(english:"RHEL 7 : texlive (RHSA-2020:1036)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2020:1036 advisory.

  - texlive: Buffer overflow in t1_check_unusual_charstring function in writet1.c (CVE-2018-17407)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17407");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1632802");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-adjustbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-adjustbox-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ae-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-algorithms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-algorithms-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-amscls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-amscls-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-amsfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-amsfonts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-amsmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-amsmath-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-anysize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-anysize-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-appendix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-appendix-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-arabxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-arabxetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-arphic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-arphic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-attachfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-attachfile-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-avantgar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-babel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-babelbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-babelbib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-beamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-beamer-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bera-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-beton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-beton-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bibtex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bibtex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bibtex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bibtopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bibtopic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bidi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bidi-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bigfoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bigfoot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-bookman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-booktabs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-booktabs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-breakurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-breakurl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-caption");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-caption-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-carlisle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-carlisle-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-changebar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-changebar-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-changepage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-changepage-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-charter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-charter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-chngcntr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-chngcntr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cjk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cm-lgc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cm-lgc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cm-super");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cm-super-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cmap-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cmextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-cns-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-collectbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-collectbox-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-collection-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-collection-documentation-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-collection-fontsrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-collection-htmlxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-collection-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-collection-latexrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-collection-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-colortbl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-colortbl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-courier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-crop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-crop-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-csquotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-csquotes-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ctable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ctable-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-currfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-currfile-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-datetime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-datetime-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipdfm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipdfm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipdfm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipdfmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipdfmx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipdfmx-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipdfmx-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipng-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvipng-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvips-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvips-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-eepic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-eepic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-enctex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-enctex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-enumitem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-enumitem-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-epsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-epsf-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-epstopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-epstopdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-epstopdf-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-eso-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-eso-pic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-etex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-etex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-etex-pkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-etex-pkg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-etoolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-etoolbox-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-euenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-euenc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-euler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-euler-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-euro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-euro-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-eurosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-eurosym-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-extsizes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-extsizes-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fancybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fancybox-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fancyhdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fancyhdr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fancyref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fancyref-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fancyvrb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fancyvrb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-filecontents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-filecontents-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-filehook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-filehook-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fix2col");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fix2col-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fixlatvian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fixlatvian-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-float");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-float-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fmtcount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fmtcount-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fncychap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fncychap-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fontbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fontbook-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fontspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fontspec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fontware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fontware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fontwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fontwrap-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-footmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-footmisc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-fpl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-framed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-framed-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-garuda-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-geometry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-geometry-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-glyphlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-graphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-graphics-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-gsftopk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-gsftopk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-helvetic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-hyperref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-hyperref-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-hyph-utf8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-hyph-utf8-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-hyphen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-hyphenat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-hyphenat-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifluatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifluatex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifmtarg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifmtarg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifoddpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifoddpage-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-iftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-iftex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ifxetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-index");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-index-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-jadetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-jadetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-jknapltx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-jknapltx-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-kastrup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-kastrup-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-kerkis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-kerkis-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-koma-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-kpathsea-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-kpathsea-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-kpathsea-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-kpathsea-lib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-l3experimental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-l3experimental-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-l3kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-l3packages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-l3packages-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lastpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lastpage-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-latex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-latex-bin-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-latex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-latex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-latex-fonts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-latexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lettrine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lettrine-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-listings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-listings-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lm-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lm-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ltxmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lua-alt-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lua-alt-getopt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lualatex-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-lualatex-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-luaotfload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-luaotfload-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-luaotfload-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-luatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-luatex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-luatex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-luatexbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-luatexbase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-makecmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-makecmds-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-makeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-makeindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-makeindex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-marginnote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-marginnote-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-marvosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-marvosym-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mathpazo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mathpazo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mathspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mathspec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mdwtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mdwtools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-memoir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-memoir-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-metafont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-metafont-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-metalogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-metalogo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-metapost-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-metapost-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-metapost-examples-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mflogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mflogo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mfnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mfnfss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mfware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mfware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mh-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-microtype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-microtype-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mnsymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mnsymbol-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mparhack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mparhack-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mptopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-mptopdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ms-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-multido");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-multido-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-multirow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-multirow-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-natbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-natbib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ncctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ncctools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ncntrsbk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-norasi-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ntgclass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ntgclass-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-oberdiek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-oberdiek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-overpic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-overpic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-palatino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-paralist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-paralist-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-parallel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-parallel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-parskip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-parskip-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-passivetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pdfpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pdfpages-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pdftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pdftex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pdftex-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pdftex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pgf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pgf-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-philokalia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-philokalia-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-placeins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-placeins-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-polyglossia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-polyglossia-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-powerdot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-powerdot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-preprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-preprint-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-psfrag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-psfrag-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pslatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-psnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-psnfss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pspicture");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pspicture-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-3d-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-blur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-blur-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-coil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-coil-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-eps-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-fill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-fill-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-grad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-grad-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-node-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-plot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-plot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-slpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-slpe-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-text-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-tree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pst-tree-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pstricks-add");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pstricks-add-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pstricks-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ptext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ptext-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pxfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-pxfonts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-qstest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-qstest-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-rcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-rcs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-realscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-realscripts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-rotating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-rotating-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-rsfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-rsfs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-sansmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-sansmath-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-sauerj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-sauerj-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-scheme-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-section");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-section-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-sectsty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-sectsty-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-seminar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-seminar-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-sepnum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-sepnum-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-setspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-setspace-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-showexpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-showexpl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-soul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-soul-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-stmaryrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-stmaryrd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-subfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-subfig-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-subfigure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-subfigure-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-svn-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-svn-prov-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-t2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-t2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tex-gyre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tex-gyre-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tex-gyre-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tex-gyre-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tex4ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tex4ht-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tex4ht-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-texconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-texconfig-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-texlive.infra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-texlive.infra-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-texlive.infra-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-textcase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-textcase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-textpos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-textpos-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-thailatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-thailatex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-threeparttable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-threeparttable-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-thumbpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-thumbpdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-thumbpdf-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-times");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tipa-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-titlesec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-titlesec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-titling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-titling-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tocloft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tocloft-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-tools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-txfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-txfonts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-type1cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-type1cm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-typehtml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-typehtml-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ucharclasses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ucharclasses-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ucs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-uhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-uhc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ulem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-ulem-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-underscore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-underscore-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-unicode-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-unicode-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-unisugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-unisugar-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-url-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-utopia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-utopia-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-varwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-varwidth-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-wadalab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-wadalab-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-was");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-was-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-wasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-wasy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-wasysym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-wasysym-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-wrapfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-wrapfig-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xcolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xcolor-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xdvi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xecjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xecjk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xecolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xecolor-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xecyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xecyr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xeindex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xepersian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xepersian-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xesearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xesearch-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex-itrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex-itrans-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex-pstricks-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex-tibetan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex-tibetan-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetexfontinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetexfontinfo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xifthen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xifthen-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xkeyval");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xkeyval-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xltxtra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xltxtra-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xmltex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xmltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xmltex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xstring-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xtab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xtab-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xunicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xunicode-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-zapfchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-zapfding");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2018-17407');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:1036');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/os',
      'content/dist/rhel/client/7/7Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/oracle-java-rm/os',
      'content/dist/rhel/client/7/7Client/x86_64/os',
      'content/dist/rhel/client/7/7Client/x86_64/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/os',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/oracle-java-rm/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/debug',
      'content/dist/rhel/power/7/7Server/ppc64/sap/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/debug',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/os',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/os',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/optional/debug',
      'content/dist/rhel/server/7/7Server/x86_64/optional/os',
      'content/dist/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/oracle-java-rm/os',
      'content/dist/rhel/server/7/7Server/x86_64/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rt/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rt/os',
      'content/dist/rhel/server/7/7Server/x86_64/rt/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/os',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/os',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/os',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/os',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/oracle-java-rm/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/os',
      'content/fastrack/rhel/client/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/os',
      'content/fastrack/rhel/client/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/os',
      'content/fastrack/rhel/computenode/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/os',
      'content/fastrack/rhel/computenode/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/os',
      'content/fastrack/rhel/server/7/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/optional/debug',
      'content/fastrack/rhel/server/7/x86_64/optional/os',
      'content/fastrack/rhel/server/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/os',
      'content/fastrack/rhel/workstation/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/os',
      'content/fastrack/rhel/workstation/7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'texlive-2012-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-2012-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-2012-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-2012-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-adjustbox-doc-svn26555.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-adjustbox-svn26555.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ae-doc-svn15878.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ae-svn15878.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-algorithms-doc-svn15878.0.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-algorithms-svn15878.0.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-amscls-doc-svn29207.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-amscls-svn29207.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-amsfonts-doc-svn29208.3.04-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-amsfonts-svn29208.3.04-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-amsmath-doc-svn29327.2.14-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-amsmath-svn29327.2.14-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-anysize-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-anysize-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-appendix-doc-svn15878.1.2b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-appendix-svn15878.1.2b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-arabxetex-doc-svn17470.v1.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-arabxetex-svn17470.v1.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-arphic-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-arphic-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-attachfile-doc-svn21866.v1.5b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-attachfile-svn21866.v1.5b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-avantgar-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-babel-doc-svn24756.3.8m-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-babel-svn24756.3.8m-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-babelbib-doc-svn25245.1.31-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-babelbib-svn25245.1.31-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-base-2012-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-beamer-doc-svn29349.3.26-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-beamer-svn29349.3.26-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bera-doc-svn20031.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bera-svn20031.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-beton-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-beton-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bibtex-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bibtex-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bibtex-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bibtex-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bibtex-doc-svn26689.0.99d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bibtex-svn26689.0.99d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bibtopic-doc-svn15878.1.1a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bibtopic-svn15878.1.1a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bidi-doc-svn29650.12.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bidi-svn29650.12.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bigfoot-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bigfoot-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-bookman-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-booktabs-doc-svn15878.1.61803-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-booktabs-svn15878.1.61803-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-breakurl-doc-svn15878.1.30-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-breakurl-svn15878.1.30-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-caption-doc-svn29026.3.3__2013_02_03_-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-caption-svn29026.3.3__2013_02_03_-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-carlisle-doc-svn18258.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-carlisle-svn18258.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-changebar-doc-svn29349.3.5c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-changebar-svn29349.3.5c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-changepage-doc-svn15878.1.0c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-changepage-svn15878.1.0c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-charter-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-charter-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-chngcntr-doc-svn17157.1.0a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-chngcntr-svn17157.1.0a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cite-doc-svn19955.5.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cite-svn19955.5.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cjk-doc-svn26296.4.8.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cjk-svn26296.4.8.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cm-doc-svn29581.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cm-lgc-doc-svn28250.0.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cm-lgc-svn28250.0.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cm-super-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cm-super-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cm-svn29581.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cmap-doc-svn26568.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cmap-svn26568.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cmextra-svn14075.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cns-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-cns-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-collectbox-doc-svn26557.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-collectbox-svn26557.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-collection-basic-svn26314.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-collection-documentation-base-svn17091.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-collection-fontsrecommended-svn28082.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-collection-htmlxml-svn28251.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-collection-latex-svn25030.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-collection-latexrecommended-svn25795.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-collection-xetex-svn29634.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-colortbl-doc-svn25394.v1.0a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-colortbl-svn25394.v1.0a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-courier-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-crop-doc-svn15878.1.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-crop-svn15878.1.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-csquotes-doc-svn24393.5.1d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-csquotes-svn24393.5.1d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ctable-doc-svn26694.1.23-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ctable-svn26694.1.23-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-currfile-doc-svn29012.0.7b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-currfile-svn29012.0.7b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-datetime-doc-svn19834.2.58-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-datetime-svn19834.2.58-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfm-bin-svn13663.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfm-doc-svn26689.0.13.2d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfm-svn26689.0.13.2d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfmx-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfmx-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfmx-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfmx-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfmx-def-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfmx-doc-svn26765.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipdfmx-svn26765.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipng-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipng-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipng-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipng-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipng-doc-svn26689.1.14-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvipng-svn26689.1.14-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvips-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvips-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvips-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvips-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvips-doc-svn29585.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-dvips-svn29585.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ec-doc-svn25033.1.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ec-svn25033.1.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-eepic-doc-svn15878.1.1e-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-eepic-svn15878.1.1e-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-enctex-doc-svn28602.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-enctex-svn28602.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-enumitem-doc-svn24146.3.5.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-enumitem-svn24146.3.5.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-epsf-doc-svn21461.2.7.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-epsf-svn21461.2.7.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-epstopdf-bin-svn18336.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-epstopdf-doc-svn26577.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-epstopdf-svn26577.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-eso-pic-doc-svn21515.2.0c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-eso-pic-svn21515.2.0c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-etex-doc-svn22198.2.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-etex-pkg-doc-svn15878.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-etex-pkg-svn15878.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-etex-svn22198.2.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-etoolbox-doc-svn20922.2.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-etoolbox-svn20922.2.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-euenc-doc-svn19795.0.1h-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-euenc-svn19795.0.1h-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-euler-doc-svn17261.2.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-euler-svn17261.2.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-euro-doc-svn22191.1.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-euro-svn22191.1.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-eurosym-doc-svn17265.1.4_subrfix-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-eurosym-svn17265.1.4_subrfix-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-extsizes-doc-svn17263.1.4a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-extsizes-svn17263.1.4a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fancybox-doc-svn18304.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fancybox-svn18304.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fancyhdr-doc-svn15878.3.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fancyhdr-svn15878.3.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fancyref-doc-svn15878.0.9c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fancyref-svn15878.0.9c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fancyvrb-doc-svn18492.2.8-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fancyvrb-svn18492.2.8-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-filecontents-doc-svn24250.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-filecontents-svn24250.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-filehook-doc-svn24280.0.5d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-filehook-svn24280.0.5d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fix2col-doc-svn17133.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fix2col-svn17133.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fixlatvian-doc-svn21631.1a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fixlatvian-svn21631.1a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-float-doc-svn15878.1.3d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-float-svn15878.1.3d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fmtcount-doc-svn28068.2.02-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fmtcount-svn28068.2.02-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fncychap-doc-svn20710.v1.34-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fncychap-svn20710.v1.34-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontbook-doc-svn23608.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontbook-svn23608.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontspec-doc-svn29412.v2.3a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontspec-svn29412.v2.3a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontware-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontware-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontware-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontware-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontware-svn26689.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontwrap-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fontwrap-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-footmisc-doc-svn23330.5.5b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-footmisc-svn23330.5.5b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fp-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fp-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fpl-doc-svn15878.1.002-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-fpl-svn15878.1.002-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-framed-doc-svn26789.0.96-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-framed-svn26789.0.96-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-garuda-c90-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-geometry-doc-svn19716.5.6-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-geometry-svn19716.5.6-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-glyphlist-svn28576.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-graphics-doc-svn25405.1.0o-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-graphics-svn25405.1.0o-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-gsftopk-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-gsftopk-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-gsftopk-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-gsftopk-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-gsftopk-svn26689.1.19.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-helvetic-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-hyperref-doc-svn28213.6.83m-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-hyperref-svn28213.6.83m-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-hyph-utf8-doc-svn29641.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-hyph-utf8-svn29641.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-hyphen-base-svn29197.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-hyphenat-doc-svn15878.2.3c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-hyphenat-svn15878.2.3c-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifetex-doc-svn24853.1.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifetex-svn24853.1.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifluatex-doc-svn26725.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifluatex-svn26725.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifmtarg-doc-svn19363.1.2a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifmtarg-svn19363.1.2a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifoddpage-doc-svn23979.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifoddpage-svn23979.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-iftex-doc-svn29654.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-iftex-svn29654.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifxetex-doc-svn19685.0.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ifxetex-svn19685.0.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-index-doc-svn24099.4.1beta-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-index-svn24099.4.1beta-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-jadetex-bin-svn3006.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-jadetex-doc-svn23409.3.13-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-jadetex-svn23409.3.13-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-jknapltx-doc-svn19440.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-jknapltx-svn19440.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kastrup-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kastrup-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kerkis-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kerkis-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-koma-script-svn27255.3.11b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kpathsea-bin-svn27347.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kpathsea-bin-svn27347.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kpathsea-bin-svn27347.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kpathsea-bin-svn27347.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kpathsea-doc-svn28792.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kpathsea-lib-2012-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kpathsea-lib-devel-2012-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-kpathsea-svn28792.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-l3experimental-doc-svn29361.SVN_4467-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-l3experimental-svn29361.SVN_4467-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-l3kernel-svn29409.SVN_4469-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-l3packages-doc-svn29361.SVN_4467-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-l3packages-svn29361.SVN_4467-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lastpage-doc-svn28985.1.2l-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lastpage-svn28985.1.2l-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-latex-bin-bin-svn14050.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-latex-bin-svn26689.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-latex-doc-svn27907.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-latex-fonts-doc-svn28888.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-latex-fonts-svn28888.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-latex-svn27907.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-latexconfig-svn28991.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lettrine-doc-svn29391.1.64-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lettrine-svn29391.1.64-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-listings-doc-svn15878.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-listings-svn15878.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lm-doc-svn28119.2.004-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lm-math-doc-svn29044.1.958-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lm-math-svn29044.1.958-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lm-svn28119.2.004-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ltxmisc-svn21927.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lua-alt-getopt-doc-svn29349.0.7.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lua-alt-getopt-svn29349.0.7.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lualatex-math-doc-svn29346.1.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-lualatex-math-svn29346.1.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luaotfload-bin-svn18579.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luaotfload-doc-svn26718.1.26-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luaotfload-svn26718.1.26-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luatex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luatex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luatex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luatex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luatex-doc-svn26689.0.70.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luatex-svn26689.0.70.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luatexbase-doc-svn22560.0.31-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-luatexbase-svn22560.0.31-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-makecmds-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-makecmds-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-makeindex-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-makeindex-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-makeindex-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-makeindex-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-makeindex-doc-svn26689.2.12-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-makeindex-svn26689.2.12-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-marginnote-doc-svn25880.v1.1i-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-marginnote-svn25880.v1.1i-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-marvosym-doc-svn29349.2.2a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-marvosym-svn29349.2.2a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mathpazo-doc-svn15878.1.003-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mathpazo-svn15878.1.003-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mathspec-doc-svn15878.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mathspec-svn15878.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mdwtools-doc-svn15878.1.05.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mdwtools-svn15878.1.05.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-memoir-doc-svn21638.3.6j_patch_6.0g-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-memoir-svn21638.3.6j_patch_6.0g-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metafont-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metafont-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metafont-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metafont-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metafont-svn26689.2.718281-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metalogo-doc-svn18611.0.12-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metalogo-svn18611.0.12-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metapost-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metapost-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metapost-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metapost-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metapost-doc-svn26689.1.212-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metapost-examples-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-metapost-svn26689.1.212-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mflogo-doc-svn17487.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mflogo-svn17487.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mfnfss-doc-svn19410.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mfnfss-svn19410.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mfware-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mfware-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mfware-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mfware-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mfware-svn26689.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mh-doc-svn29420.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mh-svn29420.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-microtype-doc-svn29392.2.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-microtype-svn29392.2.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-misc-svn24955.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mnsymbol-doc-svn18651.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mnsymbol-svn18651.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mparhack-doc-svn15878.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mparhack-svn15878.1.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mptopdf-bin-svn18674.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-mptopdf-svn26689.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ms-doc-svn24467.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ms-svn24467.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-multido-doc-svn18302.1.42-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-multido-svn18302.1.42-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-multirow-doc-svn17256.1.6-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-multirow-svn17256.1.6-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-natbib-doc-svn20668.8.31b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-natbib-svn20668.8.31b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ncctools-doc-svn15878.3.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ncctools-svn15878.3.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ncntrsbk-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-norasi-c90-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ntgclass-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ntgclass-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-oberdiek-doc-svn26725.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-oberdiek-svn26725.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-overpic-doc-svn19712.0.53-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-overpic-svn19712.0.53-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-palatino-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-paralist-doc-svn15878.2.3b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-paralist-svn15878.2.3b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-parallel-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-parallel-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-parskip-doc-svn19963.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-parskip-svn19963.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-passivetex-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pdfpages-doc-svn27574.0.4t-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pdfpages-svn27574.0.4t-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pdftex-bin-svn27321.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pdftex-bin-svn27321.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pdftex-bin-svn27321.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pdftex-bin-svn27321.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pdftex-def-svn22653.0.06d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pdftex-doc-svn29585.1.40.11-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pdftex-svn29585.1.40.11-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pgf-doc-svn22614.2.10-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pgf-svn22614.2.10-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-philokalia-doc-svn18651.1.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-philokalia-svn18651.1.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-placeins-doc-svn19848.2.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-placeins-svn19848.2.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-plain-svn26647.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-polyglossia-doc-svn26163.v1.2.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-polyglossia-svn26163.v1.2.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-powerdot-doc-svn25656.1.4i-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-powerdot-svn25656.1.4i-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-preprint-doc-svn16085.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-preprint-svn16085.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-psfrag-doc-svn15878.3.04-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-psfrag-svn15878.3.04-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pslatex-svn16416.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-psnfss-doc-svn23394.9.2a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-psnfss-svn23394.9.2a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pspicture-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pspicture-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-3d-doc-svn17257.1.10-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-3d-svn17257.1.10-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-blur-doc-svn15878.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-blur-svn15878.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-coil-doc-svn24020.1.06-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-coil-svn24020.1.06-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-eps-doc-svn15878.1.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-eps-svn15878.1.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-fill-doc-svn15878.1.01-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-fill-svn15878.1.01-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-grad-doc-svn15878.1.06-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-grad-svn15878.1.06-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-math-doc-svn20176.0.61-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-math-svn20176.0.61-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-node-doc-svn27799.1.25-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-node-svn27799.1.25-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-plot-doc-svn28729.1.44-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-plot-svn28729.1.44-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-slpe-doc-svn24391.1.31-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-slpe-svn24391.1.31-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-text-doc-svn15878.1.00-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-text-svn15878.1.00-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-tree-doc-svn24142.1.12-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pst-tree-svn24142.1.12-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pstricks-add-doc-svn28750.3.59-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pstricks-add-svn28750.3.59-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pstricks-doc-svn29678.2.39-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pstricks-svn29678.2.39-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ptext-doc-svn28124.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ptext-svn28124.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pxfonts-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-pxfonts-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-qstest-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-qstest-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-rcs-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-rcs-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-realscripts-doc-svn29423.0.3b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-realscripts-svn29423.0.3b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-rotating-doc-svn16832.2.16b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-rotating-svn16832.2.16b-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-rsfs-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-rsfs-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-sansmath-doc-svn17997.1.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-sansmath-svn17997.1.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-sauerj-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-sauerj-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-scheme-basic-svn25923.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-section-doc-svn20180.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-section-svn20180.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-sectsty-doc-svn15878.2.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-sectsty-svn15878.2.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-seminar-doc-svn18322.1.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-seminar-svn18322.1.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-sepnum-doc-svn20186.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-sepnum-svn20186.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-setspace-doc-svn24881.6.7a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-setspace-svn24881.6.7a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-showexpl-doc-svn27790.v0.3j-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-showexpl-svn27790.v0.3j-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-soul-doc-svn15878.2.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-soul-svn15878.2.4-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-stmaryrd-doc-svn22027.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-stmaryrd-svn22027.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-subfig-doc-svn15878.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-subfig-svn15878.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-subfigure-doc-svn15878.2.1.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-subfigure-svn15878.2.1.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-svn-prov-doc-svn18017.3.1862-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-svn-prov-svn18017.3.1862-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-symbol-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-t2-doc-svn29349.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-t2-svn29349.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tetex-bin-svn27344.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tetex-doc-svn29585.3.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tetex-svn29585.3.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex-gyre-doc-svn18651.2.004-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex-gyre-math-doc-svn29045.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex-gyre-math-svn29045.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex-gyre-svn18651.2.004-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex-svn26689.3.1415926-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex4ht-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex4ht-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex4ht-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex4ht-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex4ht-doc-svn29474.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tex4ht-svn29474.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-texconfig-bin-svn27344.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-texconfig-svn29349.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-texlive.infra-bin-svn22566.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-texlive.infra-bin-svn22566.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-texlive.infra-bin-svn22566.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-texlive.infra-bin-svn22566.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-texlive.infra-doc-svn28217.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-texlive.infra-svn28217.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-textcase-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-textcase-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-textpos-doc-svn28261.1.7h-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-textpos-svn28261.1.7h-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-thailatex-doc-svn29349.0.5.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-thailatex-svn29349.0.5.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-threeparttable-doc-svn17383.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-threeparttable-svn17383.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-thumbpdf-bin-svn6898.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-thumbpdf-doc-svn26689.3.15-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-thumbpdf-svn26689.3.15-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-times-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tipa-doc-svn29349.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tipa-svn29349.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-titlesec-doc-svn24852.2.10.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-titlesec-svn24852.2.10.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-titling-doc-svn15878.2.1d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-titling-svn15878.2.1d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tocloft-doc-svn20084.2.3e-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tocloft-svn20084.2.3e-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tools-doc-svn26263.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-tools-svn26263.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-txfonts-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-txfonts-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-type1cm-doc-svn21820.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-type1cm-svn21820.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-typehtml-doc-svn17134.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-typehtml-svn17134.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ucharclasses-doc-svn27820.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ucharclasses-svn27820.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ucs-doc-svn27549.2.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ucs-svn27549.2.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-uhc-doc-svn16791.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-uhc-svn16791.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ulem-doc-svn26785.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-ulem-svn26785.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-underscore-doc-svn18261.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-underscore-svn18261.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-unicode-math-doc-svn29413.0.7d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-unicode-math-svn29413.0.7d-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-unisugar-doc-svn22357.0.92-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-unisugar-svn22357.0.92-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-url-doc-svn16864.3.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-url-svn16864.3.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-utopia-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-utopia-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-varwidth-doc-svn24104.0.92-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-varwidth-svn24104.0.92-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-wadalab-doc-svn22576.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-wadalab-svn22576.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-was-doc-svn21439.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-was-svn21439.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-wasy-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-wasy-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-wasysym-doc-svn15878.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-wasysym-svn15878.2.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-wrapfig-doc-svn22048.3.6-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-wrapfig-svn22048.3.6-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xcolor-doc-svn15878.2.11-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xcolor-svn15878.2.11-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xdvi-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xdvi-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xdvi-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xdvi-bin-svn26509.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xdvi-svn26689.22.85-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xecjk-doc-svn28816.3.1.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xecjk-svn28816.3.1.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xecolor-doc-svn29660.0.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xecolor-svn29660.0.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xecyr-doc-svn20221.1.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xecyr-svn20221.1.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xeindex-doc-svn16760.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xeindex-svn16760.0.2-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xepersian-doc-svn29661.12.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xepersian-svn29661.12.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xesearch-doc-svn16041.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xesearch-svn16041.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-bin-svn26912.0-45.20130427_r30134.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-def-svn29154.0.95-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-doc-svn26330.0.9997.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-itrans-doc-svn24105.4.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-itrans-svn24105.4.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-pstricks-doc-svn17055.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-pstricks-svn17055.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-svn26330.0.9997.5-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-tibetan-doc-svn28847.0.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetex-tibetan-svn28847.0.1-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetexconfig-svn28819.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetexfontinfo-doc-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xetexfontinfo-svn15878.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xifthen-doc-svn15878.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xifthen-svn15878.1.3-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xkeyval-doc-svn27995.2.6a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xkeyval-svn27995.2.6a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xltxtra-doc-svn19809.0.5e-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xltxtra-svn19809.0.5e-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xmltex-bin-svn3006.0-45.20130427_r30134.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xmltex-doc-svn28273.0.8-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xmltex-svn28273.0.8-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xstring-doc-svn29258.1.7a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xstring-svn29258.1.7a-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xtab-doc-svn23347.2.3f-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xtab-svn23347.2.3f-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xunicode-doc-svn23897.0.981-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-xunicode-svn23897.0.981-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-zapfchan-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'texlive-zapfding-svn28614.0-45.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'texlive / texlive-adjustbox / texlive-adjustbox-doc / texlive-ae / etc');
}
