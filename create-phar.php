<?php declare(strict_types=1);

if (!class_exists('Phar') || ini_get('phar.readonly')) {
	echo "Enable PHAR extension and set directive 'phar.readonly=off'.\n";
	exit(1);
}

$fileName = 'dhcp6dump.phar';

@unlink($fileName);  # @ - file may not exist
$phar = new Phar($fileName);
$phar->setStub(
"#!/usr/bin/env php
<?php
require 'phar://' . __FILE__ . '/dhcp6dump.php';
__HALT_COMPILER();
");

$phar->startBuffering();
$phar['dhcp6dump.php'] = file_get_contents(__DIR__ . '/dhcp6dump.php');
$phar['src/DHCPv6Dumper.php'] = file_get_contents(__DIR__ . '/src/DHCPv6Dumper.php');
$phar['src/DHCPv6Messages.php'] = file_get_contents(__DIR__ . '/src/DHCPv6Messages.php');
$phar['src/DHCPv6Options.php'] = file_get_contents(__DIR__ . '/src/DHCPv6Options.php');
$phar['src/DHCPv6VendorOptions.php'] = file_get_contents(__DIR__ . '/src/DHCPv6VendorOptions.php');
$phar['src/IANAEnterpriseNumbers.php'] = file_get_contents(__DIR__ . '/src/IANAEnterpriseNumbers.php');
$phar['src/StringReader.php'] = file_get_contents(__DIR__ . '/src/StringReader.php');
$phar->stopBuffering();
$phar->compressFiles(Phar::GZ);

chmod($fileName, 0755);
