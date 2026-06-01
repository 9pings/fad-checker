#compdef fad-checker
# Zsh completion for fad-checker (Fucking Autonomous Dependency Checker)
_fad_check() {
	local -a opts
	opts=(
		'-s[root directory containing pom.xml files]:directory:_directories'
		'--src[root directory containing pom.xml files]:directory:_directories'
		'-t[output directory]:directory:_directories'
		'--target[output directory]:directory:_directories'
		'-e[regex of groupId to exclude]:regex:'
		'--exclude[regex of groupId to exclude]:regex:'
		'-a[query Maven Central]'
		'--allLibs[query Maven Central]'
		'-v[verbose]'
		'--verbose[verbose]'
		'--test[read-only]'
		'--report[generate CVE/EOL/obsolete report]'
		'--report-output[base dir for default-named outputs]:directory:_directories'
		'--report-html[write HTML report]::file:_files'
		'--report-doc[write Word .doc report]::file:_files'
		'--report-sbom[write CycloneDX 1.6 SBOM]::file:_files'
		'--report-csaf[write CSAF 2.0 VEX]::file:_files'
		'--report-json[write flat findings JSON]::file:_files'
		'--report-sarif[write SARIF 2.1.0 log]::file:_files'
		'--no-report[write no output files (gate-only)]'
		'--no-jars[skip embedded .jar/.war/.ear scanning]'
		'--no-go[skip the Go codec]'
		'--no-ruby[skip the Ruby codec]'
		'--fail-on[CI gate level]:level:(none low medium high critical kev)'
		'--ignore[suppress findings file]:file:_files'
		'--vex[ingest CSAF VEX]:file:_files'
		'--ignore-test[skip test-scoped deps]'
		'--cve-refresh[force CVE re-download]'
		'--cve-offline[use cached CVE only]'
		'--snyk[run snyk and merge]'
		'--ecosystem[codecs to run]:list:(auto all maven npm yarn nuget composer pypi)'
		'--no-maven[skip the Maven codec]'
		'--no-npm[skip the npm codec]'
		'--no-yarn[skip the Yarn codec]'
		'--no-nuget[skip the NuGet codec]'
		'--no-composer[skip the Composer codec]'
		'--no-pypi[skip the PyPI codec]'
		'--no-js[alias: skip JS/npm/yarn]'
		'--no-retire[skip retire.js vendored-JS scan]'
		'--completion[print shell completion]:shell:(bash zsh)'
	)
	_arguments $opts
}
_fad_check
