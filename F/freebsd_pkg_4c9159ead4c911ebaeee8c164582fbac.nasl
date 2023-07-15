#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(151009);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/21");

  script_cve_id("CVE-2021-3583");
  script_xref(name:"IAVB", value:"2022-B-0007");

  script_name(english:"FreeBSD : Ansible -- Templating engine bug (4c9159ea-d4c9-11eb-aeee-8c164582fbac)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Ansible developers report :

Templating engine fix for not preserving usnafe status when trying to
preserve newlines."
  );
  # https://github.com/ansible/ansible/blob/stable-2.11/changelogs/CHANGELOG-v2.11.rst#security-fixes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92f07bbb"
  );
  # https://github.com/ansible/ansible/blob/stable-2.10/changelogs/CHANGELOG-v2.10.rst#security-fixes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9914064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/ansible/ansible/pull/74960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://groups.google.com/g/ansible-announce/c/tmIgD1DpZJg"
  );
  # https://vuxml.freebsd.org/freebsd/4c9159ea-d4c9-11eb-aeee-8c164582fbac.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdc2f3f7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3583");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-ansible-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-ansible-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-ansible2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-ansible-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-ansible-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-ansible2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-ansible-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-ansible-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-ansible2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py39-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py39-ansible-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py39-ansible-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py39-ansible2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"py36-ansible-core<2.11.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-ansible-core<2.11.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-ansible-core<2.11.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py39-ansible-core<2.11.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-ansible-base<2.10.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-ansible-base<2.10.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-ansible-base<2.10.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py39-ansible-base<2.10.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-ansible2<2.9.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-ansible2<2.9.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-ansible2<2.9.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py39-ansible2<2.9.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-ansible<2.9.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-ansible<2.9.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py38-ansible<2.9.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py39-ansible<2.9.23")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:pkg_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
