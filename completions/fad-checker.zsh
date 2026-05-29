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
		'--report-output[report output dir]:directory:_directories'
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
