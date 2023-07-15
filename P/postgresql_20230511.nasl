#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# Portions Copyright (C) 1996-2019, The PostgreSQL Global Development Group
# Portions Copyright (C) 1994, The Regents of the University of California
# Permission to use, copy, modify, and distribute this software and its documentation for any purpose, without fee, and without a written agreement is hereby granted, provided that the above copyright notice and this paragraph and the following two paragraphs appear in all copies.
# IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
##

include('compat.inc');

if (description)
{
  script_id(175601);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id("CVE-2023-2454", "CVE-2023-2455");
  script_xref(name:"IAVB", value:"2023-B-0034");

  script_name(english:"PostgreSQL 11.x < 11.20 / 12.x < 12.15 / 13.x < 13.11 / 14.x < 14.8 / 15.x < 15.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PostgreSQL installed on the remote host is 11 prior to 11.20, 12 prior to 12.15, 13 prior to 13.11, 14
prior to 14.8, or 15 prior to 15.3. As such, it is potentially affected by multiple vulnerabilities :

  - CREATE SCHEMA ... schema_element defeats protective search_path changesmore details (CVE-2023-2454)

  - Row security policies disregard user ID changes after inliningmore details (CVE-2023-2455)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.postgresql.org/about/news/postgresql-153-148-1311-1215-and-1120-released-2637/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b551170c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PostgreSQL 11.20 / 12.15 / 13.11 / 14.8 / 15.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgresql_version.nbin");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
include('backport.inc');

var port = get_service(svc:'postgresql', default:5432, exit_on_fail:TRUE);
var kb_base = 'database/' + port + '/postgresql/';

var kb_ver = kb_base + 'version';
get_kb_item_or_exit(kb_ver);

var kb_backport = NULL;
var source = get_kb_item_or_exit(kb_base + 'source');
get_backport_banner(banner:source);
if (backported) kb_backport = kb_base + 'backported';

var app_info = vcf::get_app_info(app:'PostgreSQL', port:port, kb_ver:kb_ver, kb_backport:kb_backport, service:TRUE);

#  11.20 / 12.15 / 13.11 / 14.8 / 15.3
var constraints = [
  { 'min_version' : '11', 'fixed_version' : '11.20' },
  { 'min_version' : '12', 'fixed_version' : '12.15' },
  { 'min_version' : '13', 'fixed_version' : '13.11' },
  { 'min_version' : '14', 'fixed_version' : '14.8' },
  { 'min_version' : '15', 'fixed_version' : '15.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
