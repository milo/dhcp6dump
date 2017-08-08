<?php declare(strict_types=1);

if (!class_exists('Phar') || ini_get('phar.readonly')) {
	echo "Enable PHAR extension and set directive 'phar.readonly=off'.\n";
	exit(1);
}

$files = [
	'dhcp6dump.php',
	'src/DHCPv6Dumper.php',
	'src/DHCPv6Messages.php',
	'src/DHCPv6Options.php',
	'src/DHCPv6VendorOptions.php',
	'src/IANAEnterpriseNumbers.php',
	'src/StringReader.php',
];

function createPhar(string $fileName, array $files, callable $loader)
{
	$stubCode = [
		'#!/usr/bin/env php',
		'<?php',
		"Phar::mapPhar('dhcp6dump.phar');",
		"require 'phar://dhcp6dump.phar/dhcp6dump.php';",
		'__HALT_COMPILER();',
	];

	if (is_file($fileName)) {
		unlink($fileName);
	}

	$phar = new Phar($fileName);
	$phar->setStub(implode("\n", $stubCode) . "\n");
	$phar->startBuffering();
	foreach ($files as $file) {
		$phar[$file] = $loader(__DIR__ . "/$file");
	}
	$phar->stopBuffering();
	$phar->compressFiles(Phar::GZ);
	chmod($fileName, 0755);
}

createPhar('dhcp6dump.phar', $files, 'file_get_contents');
