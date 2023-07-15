#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# Portions Copyright (C) 1996-2019, The PostgreSQL Global Development Group
# Portions Copyright (C) 1994, The Regents of the University of California
# Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee, and without a written agreement is hereby granted, provided that the above copyright notice and this paragraph and the following two paragraphs appear in all copies.
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126309);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/04");

  script_cve_id("CVE-2019-10164");
  script_bugtraq_id(108875);

  script_name(english:"PostgreSQL 10.x < 10.9 / 11.x < 11.4 Stack Overflow Vulnerability (CVE-2019-10164)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a stack overflow vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 10.x prior to 10.9 or 11.x prior to 11.4. As such, it is
potentially affected by a stack overflow vulnerability. Any authenticated user can overflow a stack-based buffer by
changing the user's own password to a purpose-crafted value.

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1949/");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-10164");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 10.9 / 11.4 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10164");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgres_installed_windows.nbin", "postgres_installed_nix.nbin", "postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432, "installed_sw/PostgreSQL");

  exit(0);
}

include('vcf_extras_postgresql.inc');

var app = 'PostgreSQL';
var win_local = TRUE;

if (!get_kb_item('SMB/Registry/Enumerated'))
  win_local = FALSE;

var port = get_service(svc:'postgresql', default:5432);
var kb_base = 'database/' + port + '/postgresql/';
var kb_ver = NULL;
var kb_path = kb_base + 'version';
var ver = get_kb_item(kb_path);
if (!empty_or_null(ver)) kb_ver = kb_path;

app_info = vcf::postgresql::get_app_info(app:app, port:port, kb_ver:kb_ver, kb_base:kb_base, win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:2);

#  10.9 / 11.4
constraints = [
  { 'min_version' : '10', 'fixed_version' : '10.9' },
  { 'min_version' : '11', 'fixed_version' : '11.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
