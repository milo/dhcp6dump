<?php declare(strict_types=1);

namespace Milo\Net;


class DHCPv6Messages
{
	const
		SOLICIT = 1,
		ADVERTISE = 2,
		REQUEST = 3,
		CONFIRM = 4,
		RENEW = 5,
		REBIND = 6,
		REPLY = 7,
		RELEASE = 8,
		DECLINE = 9,
		RECONFIGURE = 10,
		INFORMATION_REQUEST = 11,
		RELAY_FORWARD = 12,
		RELAY_REPLY = 13,
		LEASEQUERY = 14,
		LEASEQUERY_REPLY = 15,
		LEASEQUERY_DONE = 16,
		LEASEQUERY_DATA = 17,
		RECONFIGURE_REQUEST = 18,
		RECONFIGURE_REPLY = 19,
		DHCPV4_QUERY = 20,
		DHCPV4_RESPONSE = 21,
		ACTIVELEASEQUERY = 22,
		STARTTLS = 23,
		BNDUPD = 24,
		BNDREPLY = 25,
		POOLREQ = 26,
		POOLRESP = 27,
		UPDREQ = 28,
		UPDREQALL = 29,
		UPDDONE = 30,
		CONNECT = 31,
		CONNECTREPLY = 31,
		DISCONNECT = 33,
		STATE = 34,
		CONTACT = 35;


	private static $names = [
		0 => '(reserved)',
		self::SOLICIT => 'SOLICIT',
		self::ADVERTISE => 'ADVERTISE',
		self::REQUEST => 'REQUEST',
		self::CONFIRM => 'CONFIRM',
		self::RENEW => 'RENEW',
		self::REBIND => 'REBIND',
		self::REPLY => 'REPLY',
		self::RELEASE => 'RELEASE',
		self::DECLINE => 'DECLINE',
		self::RECONFIGURE => 'RECONFIGURE',
		self::INFORMATION_REQUEST => 'INFORMATION-REQUEST',
		self::RELAY_FORWARD => 'RELAY-FORWARD',
		self::RELAY_REPLY => 'RELAY-REPLY',
		self::LEASEQUERY => 'LEASEQUERY',
		self::LEASEQUERY_REPLY => 'LEASEQUERY-REPLY',
		self::LEASEQUERY_DONE => 'LEASEQUERY-DONE',
		self::LEASEQUERY_DATA => 'LEASEQUERY-DATA',
		self::RECONFIGURE_REQUEST => 'RECONFIGURE-REQUEST',
		self::RECONFIGURE_REPLY => 'RECONFIGURE-REPLY',
		self::DHCPV4_QUERY => 'DHCPV4-QUERY',
		self::DHCPV4_RESPONSE => 'DHCPV4-RESPONSE',
		self::ACTIVELEASEQUERY => 'ACTIVELEASEQUERY',
		self::STARTTLS => 'STARTTLS',
		self::BNDUPD => 'BNDUPD',
		self::BNDREPLY => 'BNDREPLY',
		self::POOLREQ => 'POOLREQ',
		self::POOLRESP => 'POOLRESP',
		self::UPDREQ => 'UPDREQ',
		self::UPDREQALL => 'UPDREQALL',
		self::UPDDONE => 'UPDDONE',
		self::CONNECT => 'CONNECT',
		self::CONNECTREPLY => 'CONNECTREPLY',
		self::DISCONNECT => 'DISCONNECT',
		self::STATE => 'STATE',
		self::CONTACT => 'CONTACT',
	];


	public static function getName(int $number, string $notFound = '?'): string
	{
		return self::$names[$number] ?? $notFound;
	}
}
